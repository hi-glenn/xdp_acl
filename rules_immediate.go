package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

type NewOps struct {
	Action NewOpsAction
	Rule   Rule
}

type NewIpMapOps struct {
	Action   NewOpsAction
	Priority uint32
	AddrArr  []Addr
}

type NewPortMapOps struct {
	Action   NewOpsAction
	Priority uint32
	PortArr  []uint16
}

type NewProtoMapOps struct {
	Action   NewOpsAction
	Priority uint32
	Protos   []ProtoMapKey
}

var (
	ruleActionMapMutex sync.Mutex

	newOpsBuffer = make(chan NewOps, NEW_OPS_BUFFER_SIZE)
)

func updateIPMap(wgWorkerPtr *sync.WaitGroup, newOpsBufferForIP chan NewIpMapOps, bpfMapForIP *ebpf.Map, specialCidrMapRuleArr map[SpecialCidr][]uint32, name string) {

	zlog.Debug(name, "🍄 start 🍄")

	for newIpMapOps := range newOpsBufferForIP {

		b := time.Now()

		if NEW_OPS_ACTION_ADD == newIpMapOps.Action {
			for _, addr := range newIpMapOps.AddrArr {
				specialCidrMapRuleArrWithUpdate := make(map[SpecialCidr][]uint32)

				aSpecialCidr := addr.CidrSpecial

				newCidrRuleNoArr := []uint32{newIpMapOps.Priority}

				for bSpecialCidr, ruleArr := range specialCidrMapRuleArr {
					compareRet := compareCIDR(&aSpecialCidr, &bSpecialCidr)

					if CIDR_EQUAL == compareRet || CIDR_CONTAIN == compareRet {
						// 新项 cidr 与 遍历项 cidr 相同 || 新项 cidr 比 遍历项 cidr 大
						specialCidrMapRuleArr[bSpecialCidr] = append(ruleArr, newIpMapOps.Priority)
						specialCidrMapRuleArrWithUpdate[bSpecialCidr] = specialCidrMapRuleArr[bSpecialCidr]
					} else if CIDR_INCLUDED == compareRet {
						// 新项 cidr 比 遍历项 cidr 小
						newCidrRuleNoArr = append(newCidrRuleNoArr, ruleArr...)
						removeDupRuleNo(&newCidrRuleNoArr)
					}
					// CIDR_NO_CROSS 新项 cidr 与 遍历项 cidr 无交叉; 啥也不做
				}

				if _, ok := specialCidrMapRuleArr[aSpecialCidr]; !ok {
					specialCidrMapRuleArr[aSpecialCidr] = newCidrRuleNoArr
					specialCidrMapRuleArrWithUpdate[aSpecialCidr] = newCidrRuleNoArr
				}

				// 下发配置
				for specialCidr, ruleArr := range specialCidrMapRuleArrWithUpdate {
					var value RuleBitmapArrV4
					for ruleInx := 0; ruleInx < len(ruleArr); ruleInx++ {
						setBitmapBit(&value, ruleArr[ruleInx])
					}

					key := getLpmKey(&specialCidr)

					if err := bpfMapForIP.Put(key, &value); err != nil {
						zlog.Error(err.Error(), "; bpfMapForIP Put error")
					}
				}
			}

			zlog.Debugf("🐙 after add; %s cidrMapRuleArr: %d", name, len(specialCidrMapRuleArr))

		} else if NEW_OPS_ACTION_DEL == newIpMapOps.Action {
			for _, addr := range newIpMapOps.AddrArr {
				specialCidrMapRuleArrWithUpdate := make(map[SpecialCidr][]uint32)

				aSpecialCidr := addr.CidrSpecial

				for bSpecialCidr, ruleArr := range specialCidrMapRuleArr {

					compareRet := compareCIDR(&aSpecialCidr, &bSpecialCidr)

					if CIDR_EQUAL == compareRet || CIDR_CONTAIN == compareRet {
						// 新项 cidr 与 遍历项 cidr 相同 || 新项 cidr 比 遍历项 cidr 大
						for ruleInx := 0; ruleInx < len(ruleArr); ruleInx++ {
							if ruleArr[ruleInx] == newIpMapOps.Priority {
								ruleArr = append(ruleArr[:ruleInx], ruleArr[ruleInx+1:]...)
								break
							}
						}

						if ipMapKeyCanDel(&bSpecialCidr, name) {
							delete(specialCidrMapRuleArr, bSpecialCidr)

							specialCidrMapRuleArrWithUpdate[bSpecialCidr] = ruleArr[:0]
						} else {
							specialCidrMapRuleArr[bSpecialCidr] = ruleArr
							specialCidrMapRuleArrWithUpdate[bSpecialCidr] = ruleArr
						}
					}
					// CIDR_NO_CROSS 新项 cidr 与 遍历项 cidr 无交叉; 啥也不做
					// CIDR_INCLUDED 新项 cidr 比 遍历项 cidr 小; 啥也不做
				}

				// 下发配置
				for specialCidr, rulePriorityArr := range specialCidrMapRuleArrWithUpdate {

					key := getLpmKey(&specialCidr)

					if len(rulePriorityArr) == 0 {
						// del
						if err := bpfMapForIP.Delete(key); err != nil {
							zlog.Error(err.Error(), "; bpfMapForIP Delete error")
						}
					} else {
						// update
						var value RuleBitmapArrV4
						for ruleInx := 0; ruleInx < len(rulePriorityArr); ruleInx++ {
							setBitmapBit(&value, rulePriorityArr[ruleInx])
						}
						if err := bpfMapForIP.Put(key, &value); err != nil {
							zlog.Error(err.Error(), "; bpfMapForIP Put error")
						}
					}
				}
			}

			zlog.Debugf("🐙 after del; %s cidrMapRuleArr: %d", name, len(specialCidrMapRuleArr))

		}

		zlog.Debugf("🍉 name: %s. Cost=%+v.", name, time.Since(b))

		(*wgWorkerPtr).Done()
	}

	zlog.Debug(name, "🍊 exit 🍊")
}

func updatePortMap(wgWorkerPtr *sync.WaitGroup, newOpsBufferForPort chan NewPortMapOps, bpfMapForPort *ebpf.Map, commonPortRulePtr *RuleBitmapArrV4, specifiedPortRule map[uint16][]uint32, name string) {

	zlog.Debug(name, "🍁 start 🍁")

	var portMapKey uint16
	var portMapValue RuleBitmapArrV4

	for newPortMapOps := range newOpsBufferForPort {

		b := time.Now()

		if NEW_OPS_ACTION_ADD == newPortMapOps.Action {

			if len(newPortMapOps.PortArr) == 0 {
				setBitmapBit(commonPortRulePtr, newPortMapOps.Priority)
				// 下发配置
				for port := PORT_MIN; port <= PORT_MAX; port++ {
					portMapKey = htons(uint16(port))

					if specifiedPortRuleArr, ok := specifiedPortRule[uint16(port)]; !ok {
						if err := bpfMapForPort.Put(portMapKey, commonPortRulePtr); err != nil {
							zlog.Error(err.Error(), "; bpfMapForPort Put error")
						}
					} else {
						portMapValue = *commonPortRulePtr

						for i := 0; i < len(specifiedPortRuleArr); i++ {
							setBitmapBit(&portMapValue, specifiedPortRuleArr[i])
						}

						if err := bpfMapForPort.Put(portMapKey, &portMapValue); err != nil {
							zlog.Error(err.Error(), "; bpfMapForPort Put error")
						}
					}

				}
			} else {
				for portInx := 0; portInx < len(newPortMapOps.PortArr); portInx++ {
					specifiedPortRule[newPortMapOps.PortArr[portInx]] = append(specifiedPortRule[newPortMapOps.PortArr[portInx]], newPortMapOps.Priority)

					portMapKey = htons(newPortMapOps.PortArr[portInx])
					portMapValue = *commonPortRulePtr

					for ruleInx := 0; ruleInx < len(specifiedPortRule[newPortMapOps.PortArr[portInx]]); ruleInx++ {
						setBitmapBit(&portMapValue, specifiedPortRule[newPortMapOps.PortArr[portInx]][ruleInx])
					}

					if err := bpfMapForPort.Put(portMapKey, &portMapValue); err != nil {
						zlog.Error(err.Error(), "; bpfMapForPort Put error")
					}
				}
			}

		} else if NEW_OPS_ACTION_DEL == newPortMapOps.Action {

			if len(newPortMapOps.PortArr) == 0 {
				// 生成配置
				resetBitmapBit(commonPortRulePtr, newPortMapOps.Priority)
				// 下发配置
				for inx := PORT_MIN; inx <= PORT_MAX; inx++ {
					portMapKey = htons(uint16(inx))

					if specifiedPortRuleArr, ok := specifiedPortRule[uint16(inx)]; !ok {
						if err := bpfMapForPort.Put(portMapKey, commonPortRulePtr); err != nil {
							zlog.Error(err.Error(), "; bpfMapForPort Put error")
						}
					} else {
						portMapValue = *commonPortRulePtr
						for ruleInx := 0; ruleInx < len(specifiedPortRuleArr); ruleInx++ {
							setBitmapBit(&portMapValue, specifiedPortRuleArr[ruleInx])
						}
						if err := bpfMapForPort.Put(portMapKey, &portMapValue); err != nil {
							zlog.Error(err.Error(), "; bpfMapForPort Put error")
						}
					}
				}
			} else {
				for portInx := 0; portInx < len(newPortMapOps.PortArr); portInx++ {

					for ruleInx := 0; ruleInx < len(specifiedPortRule[newPortMapOps.PortArr[portInx]]); ruleInx++ {
						if specifiedPortRule[newPortMapOps.PortArr[portInx]][ruleInx] == newPortMapOps.Priority {
							specifiedPortRule[newPortMapOps.PortArr[portInx]] = append(specifiedPortRule[newPortMapOps.PortArr[portInx]][:ruleInx], specifiedPortRule[newPortMapOps.PortArr[portInx]][ruleInx+1:]...)

							break
						}
					}

					portMapKey = htons(newPortMapOps.PortArr[portInx])

					if len(specifiedPortRule[newPortMapOps.PortArr[portInx]]) == 0 {
						delete(specifiedPortRule, newPortMapOps.PortArr[portInx])

						if err := bpfMapForPort.Put(portMapKey, commonPortRulePtr); err != nil {
							zlog.Error(err.Error(), "; bpfMapForPort Put error")
						}
					} else {
						portMapValue = *commonPortRulePtr
						for ruleInx := 0; ruleInx < len(specifiedPortRule[newPortMapOps.PortArr[portInx]]); ruleInx++ {
							setBitmapBit(&portMapValue, specifiedPortRule[newPortMapOps.PortArr[portInx]][ruleInx])
						}

						if err := bpfMapForPort.Put(portMapKey, &portMapValue); err != nil {
							zlog.Error(err.Error(), "; bpfMapForPort Put error")
						}
					}
				}
			}
		}

		zlog.Debugf("🍉 name: %s. Cost=%+v.", name, time.Since(b))

		(*wgWorkerPtr).Done()
	}

	zlog.Debug(name, "🍁 exit 🍁")
}

func updateProtoMap(wgWorkerPtr *sync.WaitGroup, newOpsBufferForProto chan NewProtoMapOps, bpfMapForProto *ebpf.Map, name string) {

	zlog.Debug(name, "🍟 start 🍟")
	// icmp: 1; tcp: 6; udp: 17;

	for newProtoMapOps := range newOpsBufferForProto {

		var value RuleBitmapArrV4

		for i := 0; i < len(newProtoMapOps.Protos); i++ {
			if err := bpfMapForProto.Lookup(newProtoMapOps.Protos[i], &value); nil != err {
				// 此分支不应该出现，除非出错
				zlog.Error(err.Error(), "; bpfMapForProto Lookup error")
			} else {
				// key 已在初始化时添加
				if NEW_OPS_ACTION_ADD == newProtoMapOps.Action {
					setBitmapBit(&value, newProtoMapOps.Priority)
				} else {
					// NEW_OPS_ACTION_DEL
					resetBitmapBit(&value, newProtoMapOps.Priority)
				}

				zlog.Debug("🌺 ", name, "; value[0]: ", value[0], "; value[1]: ", value[1])

				if err := bpfMapForProto.Put(newProtoMapOps.Protos[i], &value); err != nil {
					zlog.Error(err.Error(), "; bpfMapForProto Put error")
				}
			}
		}

		(*wgWorkerPtr).Done()
	}

	zlog.Debug(name, "🍟 exit 🍟")
}

func getProtos(protos uint8) []ProtoMapKey {
	protoSlice := make([]ProtoMapKey, 0, 3)

	if (protos & PROTO_TCP_BIT) > 0 {
		protoSlice = append(protoSlice, ProtoMapKey(PROTO_TCP))
	}

	if (protos & PROTO_UDP_BIT) > 0 {
		protoSlice = append(protoSlice, ProtoMapKey(PROTO_UDP))
	}

	if (protos & PROTO_ICMP_BIT) > 0 {
		protoSlice = append(protoSlice, ProtoMapKey(PROTO_ICMP))
	}

	return protoSlice
}

func updateRuleActionMap(newOps *NewOps, bpfMapForRuleAction *ebpf.Map, name string) {

	var ruleActionKey RuleActionKey
	genRuleActionKey(uint64(newOps.Rule.Priority), &ruleActionKey)

	ruleActionArr := make([]RuleAction, NumCPU)
	genRuleActionValue(uint64(newOps.Rule.Strategy), &ruleActionArr)

	if NEW_OPS_ACTION_ADD == newOps.Action {
		if err := bpfMapForRuleAction.Put(ruleActionKey, ruleActionArr); err != nil {
			zlog.Error("bpfMapForRuleAction.Put: ", err)
		}
	} else {
		// NEW_OPS_ACTION_DEL
		ruleActionMapMutex.Lock()
		defer ruleActionMapMutex.Unlock()
		if err := bpfMapForRuleAction.Delete(ruleActionKey); err != nil {
			zlog.Error("bpfMapForRuleAction.Delete: ", err)
		}
	}
}

func adjustRuleList(newOps *NewOps) (string, error) {

	if NEW_OPS_ACTION_ADD == newOps.Action {
		// 添加到首部
		ruleList = append(RuleArr{newOps.Rule}, ruleList...)
	} else {
		notFindTarget := true
		for ruleInx := 0; ruleInx < len(ruleList); ruleInx++ {
			if newOps.Rule.Priority == ruleList[ruleInx].Priority {

				newOps.Rule = ruleList[ruleInx]

				ruleList = append(ruleList[:ruleInx], ruleList[ruleInx+1:]...)
				notFindTarget = false
				break
			}
		}

		if notFindTarget {
			return "", errors.New("not find specified rule: " + fmt.Sprintf("%d", newOps.Rule.Priority))
		}
	}

	if str, err := json.MarshalIndent(ruleList, "", "    "); err == nil {
		return string(str), nil
	} else {
		return "", err
	}
}

func loadImmediateRules(name string) {

	newOpsBufferForIPSrc, newOpsBufferForIPDst := make(chan NewIpMapOps, 1), make(chan NewIpMapOps, 1)

	newOpsBufferForPortSrc, newOpsBufferForPortDst := make(chan NewPortMapOps, 1), make(chan NewPortMapOps, 1)

	newOpsBufferForProto := make(chan NewProtoMapOps, 1)

	wgGlobal.Add(1)

	var immediateRuleWg, saveFileWg sync.WaitGroup

	// 启动 子协程
	go updateIPMap(&immediateRuleWg, newOpsBufferForIPSrc, objs.SrcV4, srcSpecialCidrMapInheritRuleArr, MAP_TYPE_IP_SRC)
	go updateIPMap(&immediateRuleWg, newOpsBufferForIPDst, objs.DstV4, dstSpecialCidrMapInheritRuleArr, MAP_TYPE_IP_DST)

	go updatePortMap(&immediateRuleWg, newOpsBufferForPortSrc, objs.SportV4, &commonSrcPortRule, specifiedSrcPortRule, MAP_TYPE_PORT_SRC)
	go updatePortMap(&immediateRuleWg, newOpsBufferForPortDst, objs.DportV4, &commonDstPortRule, specifiedDstPortRule, MAP_TYPE_PORT_DST)

	go updateProtoMap(&immediateRuleWg, newOpsBufferForProto, objs.ProtoV4, MAP_TYPE_PROTO)

	go saveFile(&saveFileWg)

	for newOps := range newOpsBuffer {
		zlog.Debug("---- rcv newOps")

		if NEW_OPS_ACTION_ADD != newOps.Action && NEW_OPS_ACTION_DEL != newOps.Action {
			zlog.Errorf("unknown ops rule: %d; action: %d;", newOps.Rule.Priority, newOps.Action)
			continue
		}

		// 调整 rules 列表
		if rulesStr, err := adjustRuleList(&newOps); err != nil {
			continue
		} else if err == nil && rulesStr != "" {
			saveFileWg.Add(1)

			bufferForJsonFile <- rulesStr
		}

		// ------------ 下发规则 开始
		b := time.Now()

		if NEW_OPS_ACTION_DEL == newOps.Action {
			updateRuleActionMap(&newOps, objs.RuleActionV4, MAP_TYPE_RULE_ACTION)
		}

		immediateRuleWg.Add(2)
		newOpsBufferForIPSrc <- NewIpMapOps{
			Action:   newOps.Action,
			Priority: newOps.Rule.Priority,
			AddrArr:  newOps.Rule.AddrSrcArr,
		}

		newOpsBufferForIPDst <- NewIpMapOps{
			Action:   newOps.Action,
			Priority: newOps.Rule.Priority,
			AddrArr:  newOps.Rule.AddrDstArr,
		}

		if !onlyContainICMP(newOps.Rule.Protos) {
			immediateRuleWg.Add(2)
			//  (若只有 ICMP，则不走此分支)
			newOpsBufferForPortSrc <- NewPortMapOps{
				Action:   newOps.Action,
				Priority: newOps.Rule.Priority,
				PortArr:  newOps.Rule.PortSrcArr,
			}

			newOpsBufferForPortDst <- NewPortMapOps{
				Action:   newOps.Action,
				Priority: newOps.Rule.Priority,
				PortArr:  newOps.Rule.PortDstArr,
			}
			zlog.Debug("不包含 ICMP 或者 不只ICMP")
		}

		immediateRuleWg.Add(1)
		newOpsBufferForProto <- NewProtoMapOps{
			Action:   newOps.Action,
			Priority: newOps.Rule.Priority,
			Protos:   getProtos(newOps.Rule.Protos),
		}

		immediateRuleWg.Wait()

		if NEW_OPS_ACTION_ADD == newOps.Action {
			updateRuleActionMap(&newOps, objs.RuleActionV4, MAP_TYPE_RULE_ACTION)
			zlog.Info("add rule: ", newOps.Rule.Priority, " 👌")
		} else if NEW_OPS_ACTION_DEL == newOps.Action {
			zlog.Info("del rule: ", newOps.Rule.Priority, " 👌")
		} else {
			zlog.Info("unknown ops rule: ", newOps.Rule.Priority, " 👌")
		}

		zlog.Debugf("🍉 name: %s. Cost=%+v.", "total", time.Since(b))

		// ------------ 下发规则 结束
	}

	// close 子任务 channel
	close(bufferForJsonFile)

	close(newOpsBufferForIPSrc)
	close(newOpsBufferForIPDst)
	close(newOpsBufferForPortSrc)
	close(newOpsBufferForPortDst)
	close(newOpsBufferForProto)

	saveFileWg.Wait()

	wgGlobal.Done()

	zlog.Info("takeApartRuleAndAssignWork-----exit")
}
