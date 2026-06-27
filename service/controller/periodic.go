package controller

import (
	"errors"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/xtls/xray-core/common/task"
)

const (
	periodicTaskNodeMonitor = "node monitor"
	periodicTaskUserMonitor = "user monitor"
	periodicTaskCertMonitor = "cert monitor"

	minBaseConfigPushInterval = 5
	minBaseConfigPullInterval = 30
)

type periodicRunner interface {
	Start() error
	Close() error
}

type controllerPeriodicTask struct {
	tag      string
	interval time.Duration
	Periodic periodicRunner
}

type periodicTaskFactory func(interval time.Duration, execute func() error) periodicRunner

func newControllerPeriodicTask(interval time.Duration, execute func() error) periodicRunner {
	return &task.Periodic{
		Interval: interval,
		Execute:  execute,
	}
}

func (c *Controller) periodicTaskFactory() periodicTaskFactory {
	if c == nil || c.newPeriodicTask == nil {
		return newControllerPeriodicTask
	}
	return c.newPeriodicTask
}

func (c *Controller) startPeriodicTask(tag string, periodic periodicRunner) {
	if periodic == nil {
		return
	}
	if err := periodic.Start(); err != nil && c.logger != nil {
		c.logger.WithField("task", tag).Print(err)
	}
}

func (c *Controller) launchPeriodicTask(tag string, periodic periodicRunner) {
	if _, ok := periodic.(*task.Periodic); ok {
		go c.startPeriodicTask(tag, periodic)
		return
	}
	c.startPeriodicTask(tag, periodic)
}

func (c *Controller) startOrReplacePeriodicTask(tag string, interval time.Duration, execute func() error) error {
	if interval <= 0 || execute == nil {
		return nil
	}
	periodic := c.periodicTaskFactory()(interval, execute)
	if periodic == nil {
		return nil
	}

	c.stateMu.Lock()
	for i := range c.tasks {
		if c.tasks[i].tag != tag {
			continue
		}
		if c.tasks[i].interval == interval {
			c.stateMu.Unlock()
			return nil
		}
		old := c.tasks[i].Periodic
		c.tasks[i].interval = interval
		c.tasks[i].Periodic = periodic
		c.stateMu.Unlock()
		if old != nil {
			if err := old.Close(); err != nil {
				return err
			}
		}
		if c.logger != nil {
			c.logger.Printf("Start %s periodic task", tag)
		}
		c.launchPeriodicTask(tag, periodic)
		return nil
	}
	c.tasks = append(c.tasks, periodicTask{tag: tag, interval: interval, Periodic: periodic})
	c.stateMu.Unlock()

	if c.logger != nil {
		c.logger.Printf("Start %s periodic task", tag)
	}
	c.launchPeriodicTask(tag, periodic)
	return nil
}

func (c *Controller) closePeriodicTasks() error {
	c.stateMu.Lock()
	tasks := make([]periodicTask, len(c.tasks))
	copy(tasks, c.tasks)
	c.tasks = nil
	c.stateMu.Unlock()

	var errs []error
	for i := range tasks {
		if tasks[i].Periodic == nil {
			continue
		}
		if err := tasks[i].Periodic.Close(); err != nil {
			if c.logger != nil {
				c.logger.Panicf("%s periodic task close failed: %s", tasks[i].tag, err)
			}
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *Controller) startControllerPeriodicTasks(nodeInfo *api.NodeInfo) error {
	baseConfig := c.currentBaseConfig()
	pullInterval := time.Duration(c.config.UpdatePeriodic) * time.Second
	pushInterval := pullInterval
	if baseConfig != nil {
		if normalizedPull := normalizeBaseConfigInterval(baseConfig.PullInterval, minBaseConfigPullInterval); normalizedPull > 0 {
			pullInterval = time.Duration(normalizedPull) * time.Second
		}
		if normalizedPush := normalizeBaseConfigInterval(baseConfig.PushInterval, minBaseConfigPushInterval); normalizedPush > 0 {
			pushInterval = time.Duration(normalizedPush) * time.Second
		}
	}

	if err := c.startOrReplacePeriodicTask(periodicTaskNodeMonitor, pullInterval, c.nodeInfoMonitor); err != nil {
		return err
	}
	if err := c.startOrReplacePeriodicTask(periodicTaskUserMonitor, pushInterval, c.userInfoMonitor); err != nil {
		return err
	}
	if nodeInfo != nil && nodeInfo.EnableTLS && c.config.EnableREALITY == false {
		if err := c.startOrReplacePeriodicTask(periodicTaskCertMonitor, time.Duration(c.config.UpdatePeriodic)*time.Second*60, c.certMonitor); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) currentBaseConfig() *api.BaseConfig {
	provider, ok := c.apiClient.(api.BaseConfigProvider)
	if !ok {
		return nil
	}
	return provider.GetBaseConfig()
}

func normalizeBaseConfigInterval(seconds, min int) int {
	if seconds <= 0 {
		return 0
	}
	if seconds < min {
		return min
	}
	return seconds
}

func (c *Controller) applyBaseConfig(baseConfig *api.BaseConfig) error {
	if baseConfig == nil {
		return nil
	}

	if pullInterval := normalizeBaseConfigInterval(baseConfig.PullInterval, minBaseConfigPullInterval); pullInterval > 0 {
		if err := c.startOrReplacePeriodicTask(periodicTaskNodeMonitor, time.Duration(pullInterval)*time.Second, c.nodeInfoMonitor); err != nil {
			return err
		}
	}
	if pushInterval := normalizeBaseConfigInterval(baseConfig.PushInterval, minBaseConfigPushInterval); pushInterval > 0 {
		if err := c.startOrReplacePeriodicTask(periodicTaskUserMonitor, time.Duration(pushInterval)*time.Second, c.userInfoMonitor); err != nil {
			return err
		}
	}
	return nil
}
