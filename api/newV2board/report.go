package newV2board

import (
	"errors"
	"math"
	"strconv"
	"strings"

	"github.com/Mtoly/XrayRP/api"
)

var (
	errNilNodeStatus           = errors.New("node status is nil")
	errInvalidNodeStatusNodeID = errors.New("node status node ID must be greater than 0")
	errXboardReportUnsupported = errors.New("xboard report endpoint unsupported")
)

const xboardReportPath = "/api/v2/server/report"

func buildReportStatusPayload(nodeStatus *api.NodeStatus) (map[string]any, error) {
	if nodeStatus == nil {
		return nil, errNilNodeStatus
	}

	return map[string]any{
		"type": "status",
		"status": map[string]any{
			"cpu":    nodeStatus.CPU,
			"uptime": nodeStatus.Uptime,
			"mem": map[string]int{
				"total": 100,
				"used":  clampReportPercent(nodeStatus.Mem),
			},
			"swap": map[string]int{
				"total": 0,
				"used":  0,
			},
			"disk": map[string]int{
				"total": 100,
				"used":  clampReportPercent(nodeStatus.Disk),
			},
		},
	}, nil
}

func buildNodeStatusWSPayload(nodeID int, nodeStatus *api.NodeStatus) (map[string]any, error) {
	if nodeID <= 0 {
		return nil, errInvalidNodeStatusNodeID
	}

	statusPayload, err := buildReportStatusPayload(nodeStatus)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"node_id": nodeID,
		"status":  statusPayload["status"],
	}, nil
}

func buildReportAlivePayload(onlineUsers *[]api.OnlineUser, nodeID int) map[string]any {
	return map[string]any{
		"type":  "alive",
		"alive": buildAliveMap(onlineUsers, nodeID),
	}
}

func buildReportTrafficPayload(userTraffic *[]api.UserTraffic) map[string]any {
	return map[string]any{
		"type":    "traffic",
		"traffic": buildTrafficMap(userTraffic),
	}
}

func buildAliveMap(onlineUsers *[]api.OnlineUser, nodeID int) map[int][]string {
	alive := make(map[int][]string)
	if onlineUsers == nil {
		return alive
	}

	for _, user := range *onlineUsers {
		if user.UID == 0 || user.IP == "" {
			continue
		}
		alive[user.UID] = append(alive[user.UID], user.IP+"_"+strconv.Itoa(nodeID))
	}
	return alive
}

func buildTrafficMap(userTraffic *[]api.UserTraffic) map[int][]int64 {
	trafficMap := make(map[int][]int64)
	if userTraffic == nil {
		return trafficMap
	}

	for _, traffic := range *userTraffic {
		trafficMap[traffic.UID] = []int64{traffic.Upload, traffic.Download}
	}
	return trafficMap
}

func clampReportPercent(value float64) int {
	rounded := int(math.Round(value))
	if rounded < 0 {
		return 0
	}
	if rounded > 100 {
		return 100
	}
	return rounded
}

func isReportEndpointUnsupported(statusCode int, body []byte) bool {
	switch statusCode {
	case 401, 403:
		return false
	case 404, 405, 501:
		return true
	}
	if statusCode >= 200 && statusCode < 300 {
		return false
	}

	normalized := strings.ToLower(string(body))
	unsupportedMarkers := []string{
		"not found",
		"route not found",
		"unsupported",
		"not support",
		"method not allowed",
		"not implemented",
	}
	for _, marker := range unsupportedMarkers {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func (c *APIClient) postXboardReport(payload map[string]any) error {
	res, err := c.client.R().
		SetBody(payload).
		ForceContentType("application/json").
		Post(xboardReportPath)
	if err != nil {
		return err
	}
	if isReportEndpointUnsupported(res.StatusCode(), res.Body()) {
		return errXboardReportUnsupported
	}

	_, err = c.parseResponse(res, xboardReportPath, nil)
	return err
}

// ReportNodeStatus implements the API interface.
func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) error {
	payload, err := buildReportStatusPayload(nodeStatus)
	if err != nil {
		return err
	}

	if !c.xboardReportUnsupported.Load() {
		if err := c.postXboardReport(payload); err == nil {
			return nil
		} else if errors.Is(err, errXboardReportUnsupported) {
			c.xboardReportUnsupported.Store(true)
		} else {
			return err
		}
	}

	return c.reportLegacyNodeStatus(nodeStatus)
}

// ReportNodeOnlineUsers implements the API interface.
func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {
	payload := buildReportAlivePayload(onlineUserList, c.NodeID)
	if !c.xboardReportUnsupported.Load() {
		if err := c.postXboardReport(payload); err == nil {
			return nil
		} else if errors.Is(err, errXboardReportUnsupported) {
			c.xboardReportUnsupported.Store(true)
		} else {
			return err
		}
	}

	return c.reportLegacyNodeOnlineUsers(onlineUserList)
}

// ReportUserTraffic reports the user traffic.
func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {
	payload := buildReportTrafficPayload(userTraffic)
	if !c.xboardReportUnsupported.Load() {
		if err := c.postXboardReport(payload); err == nil {
			return nil
		} else if errors.Is(err, errXboardReportUnsupported) {
			c.xboardReportUnsupported.Store(true)
		} else {
			return err
		}
	}

	return c.reportLegacyUserTraffic(userTraffic)
}

func (c *APIClient) reportLegacyNodeStatus(nodeStatus *api.NodeStatus) error {
	path := "/api/v1/server/UniProxy/status"

	payload := map[string]any{
		"cpu": nodeStatus.CPU,
		"mem": map[string]int{
			"total": 100,
			"used":  clampReportPercent(nodeStatus.Mem),
		},
		"swap": map[string]int{
			"total": 0,
			"used":  0,
		},
		"disk": map[string]int{
			"total": 100,
			"used":  clampReportPercent(nodeStatus.Disk),
		},
	}

	res, err := c.client.R().
		SetBody(payload).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	return err
}

func (c *APIClient) reportLegacyNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {
	path := "/api/v1/server/UniProxy/alive"
	data := buildAliveMap(onlineUserList, c.NodeID)

	res, err := c.client.R().
		SetBody(data).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	return err
}

func (c *APIClient) reportLegacyUserTraffic(userTraffic *[]api.UserTraffic) error {
	path := "/api/v1/server/UniProxy/push"
	data := buildTrafficMap(userTraffic)

	res, err := c.client.R().
		SetBody(data).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	return err
}
