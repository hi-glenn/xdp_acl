package main

import (
	"sort"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

func genPortConstraintsRuleArrAndLoadIntoMap(originalRulesWgPtr *sync.WaitGroup, bpfMapForPort *ebpf.Map, commonPortRulePtr *RuleBitmapArrV4, specifiedPortRule map[uint16][]uint32, name string) {
	// cpuProfile, _ := os.Create("cpu_profile1")
	// pprof.StartCPUProfile(cpuProfile)
	// defer pprof.StopCPUProfile()

	b := time.Now()

	var portSli []uint16
	for ruleInx := 0; ruleInx < len(ruleList); ruleInx++ {
		if onlyContainICMP(ruleList[ruleInx].Protos) {
			// 若只包含 ICMP
			continue
		} else {
			if name == MAP_TYPE_PORT_SRC {
				portSli = ruleList[ruleInx].PortSrcArr
			} else {
				portSli = ruleList[ruleInx].PortDstArr
			}
		}

		if len(portSli) == 0 {
			setBitmapBit(commonPortRulePtr, ruleList[ruleInx].Priority)
		} else {
			for portInx := 0; portInx < len(portSli); portInx++ {
				specifiedPortRule[portSli[portInx]] = append(specifiedPortRule[portSli[portInx]], ruleList[ruleInx].Priority)
			}
		}

		// portArr = nil
		portSli = portSli[:0]
	}

	// 下发配置
	var portMapKey uint16
	var portMapValue RuleBitmapArrV4
	for port := PORT_MIN; port <= PORT_MAX; port++ {
		portMapKey = htons(uint16(port))

		if specifiedPortRuleArr, ok := specifiedPortRule[uint16(port)]; !ok {
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

	zlog.Infof("🍉 name: %s. Cost=%+v.", name, time.Since(b))

	originalRulesWgPtr.Done()
}

func genIpConstraintsRuleArrAndLoadIntoMap(originalRulesWgPtr *sync.WaitGroup, bpfMapForIP *ebpf.Map, specialCidrMapRuleArr map[SpecialCidr][]uint32, name string) {
	/*
		{
			"specialCidr struct": [4, 5, 6],
			"specialCidr struct": [4, 5, 6, 7, 8]
		}
	*/

	// cpuProfile, _ := os.Create("cpu_profile1")
	// pprof.StartCPUProfile(cpuProfile)
	// defer pprof.StopCPUProfile()

	// f, err := os.Create("mem_profile1")
	// if err != nil {
	// 	log.Fatal("could not create memory profile: ", err)
	// }
	// runtime.GC() // get up-to-date statistics
	// if err := pprof.WriteHeapProfile(f); err != nil {
	// 	log.Fatal("could not write memory profile: ", err)
	// }
	// defer f.Close()

	b := time.Now()

	var addrArr []Addr
	var addr Addr
	var aSpecialCidr, bSpecialCidr SpecialCidr
	var ruleArr, newCidrRuleNoArr []uint32

	var compareRet CIDR_COMPARE_RET

	for ruleInx := 0; ruleInx < len(ruleList); ruleInx++ {

		if MAP_TYPE_IP_SRC == name {
			addrArr = ruleList[ruleInx].AddrSrcArr
		} else {
			addrArr = ruleList[ruleInx].AddrDstArr
		}

		for _, addr = range addrArr {
			aSpecialCidr = addr.CidrSpecial

			newCidrRuleNoArr = []uint32{ruleList[ruleInx].Priority}

			for bSpecialCidr, ruleArr = range specialCidrMapRuleArr {

				compareRet = compareCIDR(&aSpecialCidr, &bSpecialCidr)

				if CIDR_EQUAL == compareRet || CIDR_CONTAIN == compareRet {
					// 新项 cidr 与 遍历项 cidr 相同 || 新项 cidr 比 遍历项 cidr 大
					specialCidrMapRuleArr[bSpecialCidr] = append(ruleArr, ruleList[ruleInx].Priority)
				} else if CIDR_INCLUDED == compareRet {
					// 新项 cidr 比 遍历项 cidr 小
					newCidrRuleNoArr = append(newCidrRuleNoArr, ruleArr...)
					removeDupRuleNo(&newCidrRuleNoArr)
				}
				// CIDR_NO_CROSS: 新项 cidr 与 遍历项 cidr 无交叉; 啥也不做
			}

			if _, ok := specialCidrMapRuleArr[aSpecialCidr]; !ok {
				specialCidrMapRuleArr[aSpecialCidr] = newCidrRuleNoArr
			}

			ruleArr = ruleArr[:0]
			newCidrRuleNoArr = newCidrRuleNoArr[:0]
		}

		addrArr = addrArr[:0]
	}

	zlog.Debugf("🐙 original; %s cidrMapRuleArr: %d", name, len(specialCidrMapRuleArr))

	zlog.Infof("🍉 middle name: %s. Cost=%+v.", name, time.Since(b))

	for specialCidr, rulesNoArr := range specialCidrMapRuleArr {

		keyNew := getLpmKey(&specialCidr)

		var value RuleBitmapArrV4

		for i := 0; i < len(rulesNoArr); i++ {
			setBitmapBit(&value, rulesNoArr[i])
		}

		if err := bpfMapForIP.Put(keyNew, &value); err != nil {
			zlog.Error(err.Error(), "; bpfMapForIP Put error")
		}
	}

	zlog.Infof("🍉 end name: %s. Cost=%+v.", name, time.Since(b))

	originalRulesWgPtr.Done()
}

func genProtoConstraintsRuleArrAndLoadIntoMap(originalRulesWgPtr *sync.WaitGroup, bpfMapForProto *ebpf.Map, name string) {
	// 从右到左 二进制位分别表示 tcp, udp, icmp; 即 tcp: 0x01; tcp,udp: 0x03; all:0x07 |

	b := time.Now()

	var valueTCP RuleBitmapArrV4
	var valueUDP RuleBitmapArrV4
	var valueICMP RuleBitmapArrV4

	for ruleInx := 0; ruleInx < len(ruleList); ruleInx++ {
		if (ruleList[ruleInx].Protos & PROTO_TCP_BIT) > 0 {
			setBitmapBit(&valueTCP, ruleList[ruleInx].Priority)
		}

		if (ruleList[ruleInx].Protos & PROTO_UDP_BIT) > 0 {
			setBitmapBit(&valueUDP, ruleList[ruleInx].Priority)
		}

		if (ruleList[ruleInx].Protos & PROTO_ICMP_BIT) > 0 {
			setBitmapBit(&valueICMP, ruleList[ruleInx].Priority)
		}
	}

	if err := bpfMapForProto.Put(PROTO_TCP, &valueTCP); err != nil {
		zlog.Error(err.Error(), "; PROTO_TCP ProtoV4 Put error")
	}

	if err := bpfMapForProto.Put(PROTO_UDP, &valueUDP); err != nil {
		zlog.Error(err.Error(), "; PROTO_UDP ProtoV4 Put error")
	}

	if err := bpfMapForProto.Put(PROTO_ICMP, &valueICMP); err != nil {
		zlog.Error(err.Error(), "; PROTO_ICMP ProtoV4 Put error")
	}

	zlog.Debugf("🍉 name: %s. Cost=%+v.", name, time.Since(b))

	originalRulesWgPtr.Done()
}

func genRuleActionArrAndLoadIntoMap(originalRulesWgPtr *sync.WaitGroup, bpfMapForRuleAction *ebpf.Map, name string) {
	b := time.Now()
	for ruleInx := 0; ruleInx < len(ruleList); ruleInx++ {
		var ruleActionKey RuleActionKey
		genRuleActionKey(uint64(ruleList[ruleInx].Priority), &ruleActionKey)

		ruleActionArr := make([]RuleAction, NumCPU)
		genRuleActionValue(uint64(ruleList[ruleInx].Strategy), &ruleActionArr)

		if err := bpfMapForRuleAction.Put(ruleActionKey, ruleActionArr); err != nil {
			zlog.Error("bpfMapForRuleAction.Put: ", err)
		}
	}

	zlog.Debugf("🍉 name: %s. Cost=%+v.", name, time.Since(b))

	originalRulesWgPtr.Done()
}

func loadOriginalRules() {

	var originalRulesWg sync.WaitGroup

	originalRulesWg.Add(6)

	b := time.Now()

	go genPortConstraintsRuleArrAndLoadIntoMap(&originalRulesWg, objs.SportV4, &commonSrcPortRule, specifiedSrcPortRule, MAP_TYPE_PORT_SRC)
	go genPortConstraintsRuleArrAndLoadIntoMap(&originalRulesWg, objs.DportV4, &commonDstPortRule, specifiedDstPortRule, MAP_TYPE_PORT_DST)

	go genIpConstraintsRuleArrAndLoadIntoMap(&originalRulesWg, objs.SrcV4, srcSpecialCidrMapInheritRuleArr, MAP_TYPE_IP_SRC)
	go genIpConstraintsRuleArrAndLoadIntoMap(&originalRulesWg, objs.DstV4, dstSpecialCidrMapInheritRuleArr, MAP_TYPE_IP_DST)

	go genProtoConstraintsRuleArrAndLoadIntoMap(&originalRulesWg, objs.ProtoV4, MAP_TYPE_PROTO)

	go genRuleActionArrAndLoadIntoMap(&originalRulesWg, objs.RuleActionV4, MAP_TYPE_RULE_ACTION)

	originalRulesWg.Wait()

	zlog.Debugf("🍉 total Cost=%+v.", time.Since(b))
}

func preOriginalRules() {

	ruleList.Load(opt.conf)

	// 按照添加时间逆序排序（最新的在前）
	sort.Slice(ruleList, func(i, j int) bool {
		return (ruleList)[i].CreateTime > (ruleList)[j].CreateTime
	})

	// 若最后一条规则不允许用户配置
	if opt.lastRuleFixed {
		// 检查是否配置文件里有最后一条，若有则删除
		for ruleInx := 0; ruleInx < len(ruleList); ruleInx++ {
			if ruleList[ruleInx].Priority == RULE_PRIORITY_MAX {
				ruleList = append(ruleList[:ruleInx], ruleList[ruleInx+1:]...)
				break
			}
		}

		lastRule := Rule{
			Priority:   RULE_PRIORITY_MAX,
			Protos:     0b0111,
			CreateTime: time.Now().UnixNano() / 1e6,
			AddrSrcArr: []Addr{{CidrUser: "0.0.0.0/0", CidrStandard: "0.0.0.0/0"}},
			PortSrcArr: []uint16{},
			AddrDstArr: []Addr{{CidrUser: "0.0.0.0/0", CidrStandard: "0.0.0.0/0"}},
			PortDstArr: []uint16{},
			CanNotDel:  1,
		}

		if opt.lastRuleAccept {
			lastRule.Strategy = XDP_PASS
		} else {
			lastRule.Strategy = XDP_DROP
		}

		ruleList = append(ruleList, lastRule)
	}

	// 格式检查
	for ruleInx := 0; ruleInx < len(ruleList); ruleInx++ {
		if res := checkRule(&((ruleList)[ruleInx])); res != "" {
			zlog.Error(res)
			panic(res)
		}
	}
}
