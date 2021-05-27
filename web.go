package main

import (
	stdContext "context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/kataras/iris/v12"
)

type RuleActionKeyAndPriority struct {
	Key      RuleActionKey
	Priority uint32
}

type BpfMapParam struct {
	Name                        string
	IpMapKey                    LpmKeyV4
	PortMapKey                  PortMapKey
	ProtoMapKey                 ProtoMapKey
	RuleActionKeyAndPrioritySli []RuleActionKeyAndPriority
	RuleFilter                  string
}

type RuleMapInfoFiltered struct {
	Size int      `json:"size,omitempty"`
	Arr  []uint32 `json:"arr,omitempty"`
}

type RuleMapInfo struct {
	Time  string              `json:"time"`
	Set   RuleMapInfoFiltered `json:"set,omitempty"`
	Unset RuleMapInfoFiltered `json:"unset,omitempty"`
}

const (
	RULE_FILTER_SET   string = "set"
	RULE_FILTER_UNSET string = "unset"
	RULE_FILTER_ALL   string = "all"
)

type RuleActionMapInfo struct {
	Priority uint32 `json:"priority"`
	Action   uint32 `json:"action,omitempty"`
	HitCount string `json:"hit_count"`
}

type RuleActionMapInfoArr struct {
	Time          string              `json:"time"`
	Size          int                 `json:"size"`
	RuleActionArr []RuleActionMapInfo `json:"rule_action_arr"`
}

var (
	webSignal chan int
)

func webAppExit(app *iris.Application) {
	<-webSignal

	ctx, cancel := stdContext.WithCancel(stdContext.Background())

	defer cancel()

	app.Shutdown(ctx)

	zlog.Info("Shutdown web app")
}

func ruleIsLastPriorityAndIsFixed(rulePriority uint32) bool {
	if opt.lastRuleFixed && rulePriority == RULE_PRIORITY_MAX {
		return true
	}
	return false
}

func getRules(ctx iris.Context) {
	if opt.lastRuleFixed && !opt.lastRuleDisplay {
		ctx.JSON(ruleList[:len(ruleList)-1])
		return
	}
	ctx.JSON(ruleList)
}

func getHitCount(ctx iris.Context) {
	var key *RuleActionKey = nil
	var nextKey RuleActionKey

	hitCountArr := make([]RuleActionMapInfo, 0, 1024)
	var hitCount RuleActionMapInfo

	ruleActionArr := make([]RuleAction, NumCPU)

	rulePriority := uint64(0)

	ruleActionMapMutex.Lock()
	// 计算 命中次数
	for objs.RuleActionV4.NextKey(unsafe.Pointer(key), unsafe.Pointer(&nextKey)) == nil {
		if err := objs.RuleActionV4.Lookup(nextKey, &ruleActionArr); err != nil {
			zlog.Error(err.Error(), "; RuleActionV4 Lookup error")
			continue
		}

		getRulePriorityFromRuleActionKey(&nextKey, &rulePriority)

		hitCount.Priority = uint32(rulePriority)

		hitCount.HitCount = fmt.Sprintf("%d", collectHitCount(&ruleActionArr))

		hitCountArr = append(hitCountArr, hitCount)

		key = &nextKey
	}

	ruleActionMapMutex.Unlock()

	ctx.JSON(hitCountArr)
}

func addRule(ctx iris.Context) {
	var rule Rule

	if err := ctx.ReadJSON(&rule); err != nil {
		errInfo := err.Error()
		zlog.Error(errInfo)

		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{
			"errCode": 1002,
			"msg":     errInfo,
		})
		return
	}

	if ruleIsLastPriorityAndIsFixed(rule.Priority) {
		errInfo := "last rule priority is fixed, can not be set"
		zlog.Error(errInfo)

		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{
			"errCode": 1002,
			"msg":     errInfo,
		})
		return
	}

	if len(newOpsBuffer) == cap(newOpsBuffer) {
		errInfo := "buffer is full, wait a moment"
		zlog.Error(errInfo)

		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{
			"errCode": 1002,
			"msg":     errInfo,
		})
		return
	}

	if res := checkRule(&rule); res != "" {
		zlog.Error(res)

		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{
			"errCode": 1001,
			"msg":     res,
		})
		return
	}

	rule.CreateTime = time.Now().UnixNano() / 1e6

	newOpsBuffer <- NewOps{
		Action: NEW_OPS_ACTION_ADD,
		Rule:   rule,
	}

	ctx.StatusCode(iris.StatusCreated)

	ctx.JSON(rule)
}

func delRule(ctx iris.Context) {

	priorityInt, err := strconv.Atoi(ctx.Request().URL.Query().Get("priority"))
	if nil != err {
		errInfo := err.Error()
		zlog.Error(errInfo)

		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{
			"errCode": 1002,
			"msg":     errInfo,
		})
		return
	}

	rulePriority := uint32(priorityInt)

	if !rulePriorityIsValid(rulePriority) {
		errInfo := fmt.Sprintf("rulePriority: %d is out of range", rulePriority)
		zlog.Error(errInfo)

		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{
			"errCode": 1002,
			"msg":     errInfo,
		})
		return
	}

	if ruleIsLastPriorityAndIsFixed(rulePriority) {
		errInfo := "last rule priority is fixed, can not del"
		zlog.Error(errInfo)

		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{
			"errCode": 1002,
			"msg":     errInfo,
		})
		return
	}

	if len(newOpsBuffer) == cap(newOpsBuffer) {
		errInfo := "buffer is full, wait a moment"
		zlog.Error(errInfo)

		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{
			"errCode": 1002,
			"msg":     errInfo,
		})
		return
	}

	if errInfo := checkRulePriorityAndIpMapSize(rulePriority, NEW_OPS_ACTION_DEL, nil, nil); errInfo != "" {
		zlog.Error(errInfo)

		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{
			"errCode": 1003,
			"msg":     errInfo,
		})
		return
	}

	var rule Rule
	rule.Priority = rulePriority

	newOpsBuffer <- NewOps{
		Action: NEW_OPS_ACTION_DEL,
		Rule:   rule,
	}

	ctx.JSON(struct {
		Priority int32 `json:"priority"`
	}{Priority: int32(priorityInt)})

}

func checkMapParams(ctx iris.Context, bpfMapParamPtr *BpfMapParam) string {
	/*
		mapName:
		"ip_src" "ip_dst"    cidr
		"port_src" "port_dst"  port
		"proto"     tcp/udp/icmp
		"rule_action" number
	*/

	// check map name
	mapName := ctx.Params().Get("name")
	if mapName == MAP_TYPE_IP_SRC || mapName == MAP_TYPE_IP_DST ||
		mapName == MAP_TYPE_PORT_SRC || mapName == MAP_TYPE_PORT_DST ||
		mapName == MAP_TYPE_PROTO || mapName == MAP_TYPE_RULE_ACTION {
		goto next
	} else {
		return fmt.Sprintf("mapName: %s is invalid", mapName)
	}

next:
	bpfMapParamPtr.Name = mapName

	// check map key
	mapKey := ctx.Request().URL.Query().Get("key")
	if mapName == MAP_TYPE_RULE_ACTION {
		rulePriorityStrSli := strings.Split(mapKey, ",")
		for ruleStrInx := 0; ruleStrInx < len(rulePriorityStrSli); ruleStrInx++ {
			if tmpPriority, err := strconv.ParseUint(rulePriorityStrSli[ruleStrInx], 10, 32); err != nil {
				return err.Error()
			} else {
				if !rulePriorityIsValid(uint32(tmpPriority)) {
					return fmt.Sprintf("rulePriority: %d is invalid", tmpPriority)
				}

				var ruleActionMapKey RuleActionKey
				genRuleActionKey(tmpPriority, &ruleActionMapKey)

				bpfMapParamPtr.RuleActionKeyAndPrioritySli = append(bpfMapParamPtr.RuleActionKeyAndPrioritySli, RuleActionKeyAndPriority{Priority: uint32(tmpPriority), Key: ruleActionMapKey})
			}
		}
	} else {
		bpfMapParamPtr.RuleFilter = ctx.Request().URL.Query().Get("filter")
		if bpfMapParamPtr.RuleFilter != RULE_FILTER_SET && bpfMapParamPtr.RuleFilter != RULE_FILTER_UNSET && bpfMapParamPtr.RuleFilter != RULE_FILTER_ALL {
			return fmt.Sprintf("filter: %s is invalid", bpfMapParamPtr.RuleFilter)
		}

		if mapName == MAP_TYPE_IP_SRC || mapName == MAP_TYPE_IP_DST {
			if _, netNo, err := net.ParseCIDR(mapKey); err != nil {
				return fmt.Sprintf("mapKey: %s is invalid; err: %s", mapKey, err.Error())
			} else {
				var cidrSpecial SpecialCidr

				copy(cidrSpecial.First[:], netNo.IP.To4())
				lastAddr(netNo, &(cidrSpecial.Last))
				copy(cidrSpecial.MaskBits[:], net.IP(netNo.Mask).To4())
				maskSize, _ := netNo.Mask.Size()
				cidrSpecial.MaskSize = uint32(maskSize)

				bpfMapParamPtr.IpMapKey = getLpmKey(&cidrSpecial)
			}

		} else if mapName == MAP_TYPE_PORT_SRC || mapName == MAP_TYPE_PORT_DST {

			if tmpPort, err := strconv.ParseUint(mapKey, 10, 16); err != nil {
				return fmt.Sprintf("mapKey: %s is invalid; err: %s", mapKey, err.Error())
			} else {
				if tmpPort < uint64(PORT_MIN) || tmpPort > uint64(PORT_MAX) {
					return fmt.Sprintf("mapKey/port: %s is invalid;", mapKey)
				}
				bpfMapParamPtr.PortMapKey = PortMapKey(htons(uint16(tmpPort)))
			}

		} else {
			// MAP_TYPE_PROTO
			if mapKey == "tcp" {
				bpfMapParamPtr.ProtoMapKey = PROTO_TCP
			} else if mapKey == "udp" {
				bpfMapParamPtr.ProtoMapKey = PROTO_UDP
			} else if mapKey == "icmp" {
				bpfMapParamPtr.ProtoMapKey = PROTO_ICMP
			} else {
				return fmt.Sprintf("mapKey: %s is invalid;", mapKey)
			}
		}
	}

	return ""
}

func collectHitCount(ruleActionSliPtr *[]RuleAction) uint64 {
	hitCount := uint64(0)
	for inx := 0; inx < len(*ruleActionSliPtr); inx++ {
		hitCount += (*ruleActionSliPtr)[inx].Count
	}
	return hitCount
}

func getRulePriorityFromBitmap(ruleBitmapArrPtr *RuleBitmapArrV4, filter string, ruleRes *RuleMapInfo) {
	ruleRes.Time = time.Now().Format("2006-01-02 15:04:05")

	for ruleInx := RULE_PRIORITY_MIN; ruleInx <= RULE_PRIORITY_MAX; ruleInx++ {
		if getBitmapBit(ruleBitmapArrPtr, ruleInx) {
			// set
			if filter == RULE_FILTER_SET || filter == RULE_FILTER_ALL {
				ruleRes.Set.Arr = append(ruleRes.Set.Arr, ruleInx)
			}
		} else {
			// unset
			if filter == RULE_FILTER_UNSET || filter == RULE_FILTER_ALL {
				ruleRes.Unset.Arr = append(ruleRes.Unset.Arr, ruleInx)
			}
		}
	}

	if len(ruleRes.Set.Arr) > 0 {
		ruleRes.Set.Size = len(ruleRes.Set.Arr)
	}

	if len(ruleRes.Unset.Arr) > 0 {
		ruleRes.Unset.Size = len(ruleRes.Unset.Arr)
	}
}

func getBpfMapData(ctx iris.Context) {

	var bpfMapParam BpfMapParam

	if errInfo := checkMapParams(ctx, &bpfMapParam); errInfo != "" {
		zlog.Error(errInfo)
		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{
			"errCode": 1003,
			"msg":     errInfo,
		})

		return
	}

	var err error
	var ruleValue RuleBitmapArrV4

	switch bpfMapParam.Name {
	case MAP_TYPE_IP_SRC:
		err = objs.SrcV4.Lookup(bpfMapParam.IpMapKey, &ruleValue)
	case MAP_TYPE_IP_DST:
		err = objs.DstV4.Lookup(bpfMapParam.IpMapKey, &ruleValue)
	case MAP_TYPE_PORT_SRC:
		err = objs.SportV4.Lookup(bpfMapParam.PortMapKey, &ruleValue)
	case MAP_TYPE_PORT_DST:
		err = objs.DportV4.Lookup(bpfMapParam.PortMapKey, &ruleValue)
	case MAP_TYPE_PROTO:
		err = objs.ProtoV4.Lookup(bpfMapParam.ProtoMapKey, &ruleValue)
	case MAP_TYPE_RULE_ACTION:
		ruleActionSli := make([]RuleAction, NumCPU)
		ruleInfoSli := make([]RuleActionMapInfo, 0, 32)

		for _, ruleActionKeyAndPriority := range bpfMapParam.RuleActionKeyAndPrioritySli {
			if err = objs.RuleActionV4.Lookup(ruleActionKeyAndPriority.Key, &ruleActionSli); err != nil {
				continue
			}

			ruleInfo := RuleActionMapInfo{
				HitCount: fmt.Sprintf("%d", collectHitCount(&ruleActionSli)),
				Action:   uint32(ruleActionSli[0].Action),
				Priority: ruleActionKeyAndPriority.Priority,
			}

			ruleInfoSli = append(ruleInfoSli, ruleInfo)
		}

		ctx.JSON(RuleActionMapInfoArr{Time: time.Now().Format("2006-01-02 15:04:05"), Size: len(ruleInfoSli), RuleActionArr: ruleInfoSli})

		return
	}

	if err != nil {
		errInfo := fmt.Sprintf("mapName: %s; err: %s", bpfMapParam.Name, err.Error())
		zlog.Error(errInfo)

		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{
			"errCode": 1003,
			"msg":     errInfo,
		})

		return
	}

	var ruleRes RuleMapInfo

	getRulePriorityFromBitmap(&ruleValue, bpfMapParam.RuleFilter, &ruleRes)

	ctx.JSON(ruleRes)

}

func webInit(opt *CliParams) {

	app := iris.New()

	go webAppExit(app)

	app.HandleDir("/", "./public", iris.DirOptions{
		Gzip:      true,
		IndexName: "index.html",
	})

	v1 := app.Party("/xdp-acl")

	v1.Use(iris.Gzip)

	v1.Get("/IPv4/rules", getRules)

	v1.Get("/IPv4/rules/hitcount", getHitCount)

	v1.Post("/IPv4/rule", addRule)

	v1.Delete("/IPv4/rule", delRule)

	// debug assist
	v1.Get("/IPv4/bpfmap/{name:string}", getBpfMapData)

	zlog.Infof("Start web server listening on http://%s:%d", opt.server, opt.port)

	if err := app.Run(iris.Addr(fmt.Sprintf("%s:%d", opt.server, opt.port)), iris.WithConfiguration(iris.Configuration{
		DisableAutoFireStatusCode: true,
	})); err != nil {
		if err.Error() != "http: Server closed" {
			zlog.Error(err.Error(), "; web server start error")

			// todo 捕捉端口占用错误 直接 退出，此处 panic 未卸载 xdp
			panic(err.Error())
		} else {
			zlog.Infof("web server is closed")
		}
	}

}

// jsonBytes, err := json.Marshal(rules)
// if err != nil {
// 	zlog.Error(err)
// }
// ctx.WriteGzip(jsonBytes)

// if ctx.ClientSupportsGzip() {
// 	zlog.Info("client support Gzip")
// } else {
// 	zlog.Info("client not support Gzip")
// }
