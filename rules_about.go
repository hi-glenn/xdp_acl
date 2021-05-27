package main

import (
	"fmt"
	"net"
	"sync"
)

const (
	// BITMAP_ARRAY_SIZE, 必须与 XDP 程序定义一致
	BITMAP_ARRAY_SIZE uint32 = 160

	BITMAP_SIZE        = 64
	BITMAP_MASK        = 63
	ULL1_64     uint64 = 1

	// 必须与 XDP 程序中 IP_MAX_ENTRIES_V4 保持一致
	SRC_IP_MAP_MAX_ENTRIES = BITMAP_ARRAY_SIZE * BITMAP_SIZE
	DST_IP_MAP_MAX_ENTRIES = BITMAP_ARRAY_SIZE * BITMAP_SIZE

	RULE_PRIORITY_MAX uint32 = BITMAP_ARRAY_SIZE*BITMAP_SIZE - 1
	RULE_PRIORITY_MIN uint32 = 1

	MAP_TYPE_IP_SRC      = "ip_src"
	MAP_TYPE_IP_DST      = "ip_dst"
	MAP_TYPE_PORT_SRC    = "port_src"
	MAP_TYPE_PORT_DST    = "port_dst"
	MAP_TYPE_PROTO       = "proto"
	MAP_TYPE_RULE_ACTION = "rule_action"

	PROTO_ICMP ProtoMapKey = 1
	PROTO_TCP  ProtoMapKey = 6
	PROTO_UDP  ProtoMapKey = 17

	PROTO_TCP_BIT  uint8 = 0b0001
	PROTO_UDP_BIT  uint8 = 0b0010
	PROTO_ICMP_BIT uint8 = 0b0100

	NEW_OPS_ACTION_ADD NewOpsAction = 1
	NEW_OPS_ACTION_DEL NewOpsAction = 2

	NEW_OPS_BUFFER_SIZE = 2048

	PORT_MIN uint32 = 0
	PORT_MAX uint32 = 65535
)

type RuleBitmapArrV4 [BITMAP_ARRAY_SIZE]uint64

type NewOpsAction uint8

type SpecialCidr struct {
	First    [4]byte
	Last     [4]byte
	MaskBits [4]byte
	MaskSize uint32
}

type Addr struct {
	CidrUser     string      `json:"cidr_user"`
	CidrStandard string      `json:"cidr_standard"`
	CidrSpecial  SpecialCidr `json:"-"`
}

type Rule struct {
	Priority   uint32   `json:"priority"`
	Strategy   uint8    `json:"strategy"`
	Protos     uint8    `json:"protos"`
	CreateTime int64    `json:"create_time"`
	AddrSrcArr []Addr   `json:"addr_src_arr"`
	PortSrcArr []uint16 `json:"port_src_arr"`
	AddrDstArr []Addr   `json:"addr_dst_arr"`
	PortDstArr []uint16 `json:"port_dst_arr"`
	HitCounts  string   `json:"-"`
	CanNotDel  uint8    `json:"can_not_del,omitempty"`
}

type RuleArr []Rule

var (
	bufferForJsonFile = make(chan string, 100)

	ruleList        = make(RuleArr, 0, 1024)
	rulePrioritySet = make(map[uint32]uint8, 1024)

	rulePriorityMutex sync.Mutex

	commonSrcPortRule RuleBitmapArrV4
	commonDstPortRule RuleBitmapArrV4

	specifiedSrcPortRule = make(map[uint16][]uint32, 1024)
	specifiedDstPortRule = make(map[uint16][]uint32, 1024)

	srcSpecialCidrMapInheritRuleArr = make(map[SpecialCidr][]uint32, 1024)
	dstSpecialCidrMapInheritRuleArr = make(map[SpecialCidr][]uint32, 1024)

	srcCidrMapOwnRuleArrAdvance = make(map[SpecialCidr][]uint32, 1024)
	dstCidrMapOwnRuleArrAdvance = make(map[SpecialCidr][]uint32, 1024)
)

func rulePriorityIsValid(rulePriority uint32) bool {
	if rulePriority >= RULE_PRIORITY_MIN && rulePriority <= RULE_PRIORITY_MAX {
		return true
	}
	return false
}

func delRulePriorityFromCidrMapOwnRuleArrAdvance(rulePriority uint32, cidrMapOwnRuleArrAdvance map[SpecialCidr][]uint32) {
	for delCidr := range cidrMapOwnRuleArrAdvance {

		for ruleInx := 0; ruleInx < len(cidrMapOwnRuleArrAdvance[delCidr]); ruleInx++ {

			if rulePriority == cidrMapOwnRuleArrAdvance[delCidr][ruleInx] {
				cidrMapOwnRuleArrAdvance[delCidr] = append(cidrMapOwnRuleArrAdvance[delCidr][:ruleInx], cidrMapOwnRuleArrAdvance[delCidr][ruleInx+1:]...)
				if len(cidrMapOwnRuleArrAdvance[delCidr]) == 0 {
					delete(cidrMapOwnRuleArrAdvance, delCidr)
				}
			}

		}

	}
}

func checkIpMapMaxSize(rulePriority uint32, srcCidrMapTmp, dstCidrMapTmp map[SpecialCidr]uint8) string {
	// 计算新 src cidr 个数
	newSrcCidrNum := 0
	var specialCidr SpecialCidr
	for specialCidr = range srcCidrMapTmp {
		if _, ok := srcCidrMapOwnRuleArrAdvance[specialCidr]; !ok {
			newSrcCidrNum++
		}
	}

	// 计算新 dst cidr 个数
	newDstCidrNum := 0
	for specialCidr = range dstCidrMapTmp {
		if _, ok := dstCidrMapOwnRuleArrAdvance[specialCidr]; !ok {
			newDstCidrNum++
		}
	}

	// 检查 src IP 是否超出 src IP map 限制
	if uint32(len(srcCidrMapOwnRuleArrAdvance)+newSrcCidrNum) > SRC_IP_MAP_MAX_ENTRIES {
		return fmt.Sprintf("rulePriority: %d; nums: %d exceed src IP map size: %d;", rulePriority, uint32(len(srcCidrMapOwnRuleArrAdvance)+newSrcCidrNum), SRC_IP_MAP_MAX_ENTRIES)
	}

	// 检查 dst IP 是否超出 dst IP map 限制
	if uint32(len(dstCidrMapOwnRuleArrAdvance)+newDstCidrNum) > DST_IP_MAP_MAX_ENTRIES {
		return fmt.Sprintf("rulePriority: %d; nums: %d exceed dst IP map size: %d;", rulePriority, uint32(len(dstCidrMapOwnRuleArrAdvance)+newDstCidrNum), DST_IP_MAP_MAX_ENTRIES)
	}

	return ""
}

func checkRulePriorityAndIpMapSize(rulePriority uint32, action NewOpsAction, srcSpecialCidrMapTmp, dstSpecialCidrMapTmp map[SpecialCidr]uint8) string {
	rulePriorityMutex.Lock()
	defer rulePriorityMutex.Unlock()

	errInfo := ""
	if action == NEW_OPS_ACTION_DEL {
		// 删除 规则
		if _, ok := rulePrioritySet[rulePriority]; !ok {
			errInfo = fmt.Sprintf("rulePriority: %d not exist", rulePriority)
		} else {
			delRulePriorityFromCidrMapOwnRuleArrAdvance(rulePriority, srcCidrMapOwnRuleArrAdvance)
			delRulePriorityFromCidrMapOwnRuleArrAdvance(rulePriority, dstCidrMapOwnRuleArrAdvance)

			delete(rulePrioritySet, rulePriority)

			zlog.Debugf("🐙 after del srcCidrMapOwnRuleArrAdvance: %d; dstCidrMapOwnRuleArrAdvance: %d; rulePrioritySet: %d", len(srcCidrMapOwnRuleArrAdvance), len(dstCidrMapOwnRuleArrAdvance), len(rulePrioritySet))
		}
	} else {
		// 新增规则 NewOpsActionAdd
		if _, ok := rulePrioritySet[rulePriority]; ok {
			errInfo = fmt.Sprintf("rulePriority: %d has exist", rulePriority)
		} else {
			//  计数 cidr

			if errInfo = checkIpMapMaxSize(rulePriority, srcSpecialCidrMapTmp, dstSpecialCidrMapTmp); errInfo == "" {
				// add RulePriority into CidrMapOwnRuleArrAdvance
				var specialCidr SpecialCidr
				for specialCidr = range srcSpecialCidrMapTmp {
					srcCidrMapOwnRuleArrAdvance[specialCidr] = append(srcCidrMapOwnRuleArrAdvance[specialCidr], rulePriority)
				}

				for specialCidr = range dstSpecialCidrMapTmp {
					dstCidrMapOwnRuleArrAdvance[specialCidr] = append(dstCidrMapOwnRuleArrAdvance[specialCidr], rulePriority)
				}

				rulePrioritySet[rulePriority] = 1
			}

			zlog.Debugf("🐙 after add srcCidrMapOwnRuleArrAdvance: %d; dstCidrMapOwnRuleArrAdvance: %d; rulePrioritySet: %d", len(srcCidrMapOwnRuleArrAdvance), len(dstCidrMapOwnRuleArrAdvance), len(rulePrioritySet))
		}
	}

	return errInfo
}

func checkCidrValidAndCidrRelation(rulePriority uint32, specialCidrMapTmp map[SpecialCidr]uint8, addrArr *[]Addr, name string) string {

	// cidr 是否相互包含
	for addrInx := 0; addrInx < len(*addrArr); addrInx++ {
		_, ipv4NetNew, err := net.ParseCIDR((*addrArr)[addrInx].CidrUser)
		if err != nil {
			return fmt.Sprintf("rulePriority: %d; name: %s; cidr: %s", rulePriority, name, err.Error())
		}

		(*addrArr)[addrInx].CidrStandard = ipv4NetNew.String()

		// first addr
		copy((*addrArr)[addrInx].CidrSpecial.First[:], ipv4NetNew.IP.To4())
		// last addr
		lastAddr(ipv4NetNew, &((*addrArr)[addrInx].CidrSpecial.Last))
		// mask bits
		copy((*addrArr)[addrInx].CidrSpecial.MaskBits[:], net.IP(ipv4NetNew.Mask).To4())
		// mask size
		maskSize, _ := ipv4NetNew.Mask.Size()
		(*addrArr)[addrInx].CidrSpecial.MaskSize = uint32(maskSize)

		for specialCidr := range specialCidrMapTmp {
			compareRet := compareCIDR(&((*addrArr)[addrInx].CidrSpecial), &specialCidr)

			if compareRet == CIDR_CONTAIN || compareRet == CIDR_EQUAL || compareRet == CIDR_INCLUDED {
				return fmt.Sprintf("rulePriority: %d; name: %s; cidr: %s and cidr: %s has inclusion relation", rulePriority, name, ipv4NetNew.String(), specialCidr.standardCidr())
			}
		}
		specialCidrMapTmp[((*addrArr)[addrInx].CidrSpecial)] = 1
	}

	return ""
}

func checkRule(rule *Rule) string {
	// golang 编译器会自动识别是 指针 还是 struct 对象

	// 优先级是否在范围内
	if !rulePriorityIsValid(rule.Priority) {
		return fmt.Sprintf("rulePriority: %d is out of range", rule.Priority)
	}

	// 协议检查
	if (rule.Protos>>3) > 0 || (rule.Protos&0b0111 == 0) {
		return fmt.Sprintf("rulePriority: %d; unknown protos: 0x%0x;", rule.Priority, rule.Protos)
	}

	// action 检查
	if XDP_DROP != rule.Strategy && XDP_PASS != rule.Strategy {
		return fmt.Sprintf("rulePriority: %d; unknown strategy: %d;", rule.Priority, rule.Strategy)
	}

	// 检查 src IP 与 dst IP 是否为空数组
	if len(rule.AddrSrcArr) == 0 || len(rule.AddrDstArr) == 0 {
		return fmt.Sprintf("rulePriority: %d; src IP or dst IP is null;", rule.Priority)
	}

	// 检查 src IP 是否合法 和 src cidr 是否重复
	srcSpecialCidrMapTmp := make(map[SpecialCidr]uint8, 16)
	if errInfo := checkCidrValidAndCidrRelation(rule.Priority, srcSpecialCidrMapTmp, &(rule.AddrSrcArr), "src"); errInfo != "" {
		return errInfo
	}

	// 检查 dst IP 是否合法 和 dst cidr 是否重复
	dstSpecialCidrMapTmp := make(map[SpecialCidr]uint8, 16)
	if errInfo := checkCidrValidAndCidrRelation(rule.Priority, dstSpecialCidrMapTmp, &(rule.AddrDstArr), "dst"); errInfo != "" {
		return errInfo
	}

	// rule priority 查重 并 添加
	if errInfo := checkRulePriorityAndIpMapSize(rule.Priority, NEW_OPS_ACTION_ADD, srcSpecialCidrMapTmp, dstSpecialCidrMapTmp); errInfo != "" {
		return errInfo
	}

	if opt.lastRuleFixed && rule.Priority == RULE_PRIORITY_MAX {
		rule.CanNotDel = 1
	} else {
		rule.CanNotDel = 0
	}

	return ""
}
