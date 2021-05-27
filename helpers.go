package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

type CIDR_COMPARE_RET int

const (
	CIDR_EQUAL    CIDR_COMPARE_RET = 1
	CIDR_NO_CROSS CIDR_COMPARE_RET = 2
	CIDR_CONTAIN  CIDR_COMPARE_RET = 3
	CIDR_INCLUDED CIDR_COMPARE_RET = 4
	CIDR_UNKNOWN  CIDR_COMPARE_RET = 5
)

// host to network byte order
func htons(h uint16) uint16 {
	data := make([]byte, 2)
	binary.LittleEndian.PutUint16(data, h)
	return binary.BigEndian.Uint16(data)
}

// network to host byte order
func ntohs(n uint16) uint16 {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, n)
	return binary.LittleEndian.Uint16(data)
}

// 置位 第 n 位 (1)
func setBitmapBit(bitmapArr *RuleBitmapArrV4, n uint32) {
	//  n/BITMAP_SIZE 等价于 n>>6
	(*bitmapArr)[n>>6] |= (ULL1_64 << (n & BITMAP_MASK))
}

// 复位 第 n 位 (0)
func resetBitmapBit(bitmapArr *RuleBitmapArrV4, n uint32) {
	//  n/BITMAP_SIZE 等价于 n>>6
	(*bitmapArr)[n>>6] &= ^(ULL1_64 << (n & BITMAP_MASK))
}

// 获取第 n 位 0/1
func getBitmapBit(bitmapArr *RuleBitmapArrV4, n uint32) bool {
	return ((*bitmapArr)[n>>6] & (ULL1_64 << (n & BITMAP_MASK))) > 0
}

func lastAddr(n *net.IPNet, lastAddrPtr *[4]byte) {
	netNo := n.IP.To4()
	mask := net.IP(n.Mask).To4()

	*lastAddrPtr = [4]byte{(netNo[0] | (^mask[0])), (netNo[1] | (^mask[1])), (netNo[2] | (^mask[2])), (netNo[3] | (^mask[3]))}
}

func (a *SpecialCidr) contains(b *SpecialCidr) bool {
	if a.First[0] != (a.MaskBits[0]&b.First[0]) || a.First[0] != (a.MaskBits[0]&b.Last[0]) {
		return false
	}

	if a.First[1] != (a.MaskBits[1]&b.First[1]) || a.First[1] != (a.MaskBits[1]&b.Last[1]) {
		return false
	}

	if a.First[2] != (a.MaskBits[2]&b.First[2]) || a.First[2] != (a.MaskBits[2]&b.Last[2]) {
		return false
	}

	if a.First[3] != (a.MaskBits[3]&b.First[3]) || a.First[3] != (a.MaskBits[3]&b.Last[3]) {
		return false
	}

	return true
}

func compareCIDR(a, b *SpecialCidr) CIDR_COMPARE_RET {

	if a.First == b.First && a.MaskSize == b.MaskSize {
		return CIDR_EQUAL
	} else if a.contains(b) {
		return CIDR_CONTAIN
	} else if b.contains(a) {
		return CIDR_INCLUDED
	} else {
		return CIDR_NO_CROSS
	}

}

func removeDupRuleNo(rulesNoArr *[]uint32) {
	tmpSet := make(map[uint32]uint8, 1024)
	tmpSlice := make([]uint32, 0, 1024)

	for i := 0; i < len(*rulesNoArr); i++ {
		if _, ok := tmpSet[(*rulesNoArr)[i]]; !ok {
			tmpSet[(*rulesNoArr)[i]] = 1
			tmpSlice = append(tmpSlice, (*rulesNoArr)[i])
		}
	}

	*rulesNoArr = tmpSlice
}

// 只有 ICMP
func onlyContainICMP(protos uint8) bool {
	// 包含 ICMP 并且 不包含 TCP、UDP
	return ((protos & 0b0100) > 0) && ((protos & 0b0011) == 0)
}

func genRuleActionKey(priority uint64, ruleActionKey *RuleActionKey) {
	ruleActionKey.BitmapFFS = ULL1_64 << (priority & BITMAP_MASK)

	ruleActionKey.BitmapArrayInx = priority / BITMAP_SIZE
}

func genRuleActionValue(strategy uint64, ruleActionArr *[]RuleAction) {
	for i := 0; i < NumCPU; i++ {
		(*ruleActionArr)[i].Action = strategy
		(*ruleActionArr)[i].Count = 0
	}
	// zlog.Debug(" 🤗 action 🤗: ", strategy)
}

// todo 优化
func getRulePriorityFromRuleActionKey(ruleActionKey *RuleActionKey, rulePriority *uint64) {

	inx := uint64(0)
	for ; inx < BITMAP_SIZE; inx++ {
		if (ruleActionKey.BitmapFFS>>inx)&0x01 > 0 {
			break
		}
	}

	if inx == BITMAP_SIZE {
		// 正常情况下，此分支不可能进入
		zlog.Error("❌ inx == BITMAP_SIZE == ", BITMAP_SIZE)
	}

	*rulePriority = ruleActionKey.BitmapArrayInx*BITMAP_SIZE + inx
}

func ipMapKeyCanDel(delSpecialCidr *SpecialCidr, mapName string) bool {
	//  确认没有 CIDR 与 待删除 CIDR 相同

	var addrArr []Addr
	for ruleInx := 0; ruleInx < len(ruleList); ruleInx++ {
		if MAP_TYPE_IP_SRC == mapName {
			addrArr = ruleList[ruleInx].AddrSrcArr
		} else {
			addrArr = ruleList[ruleInx].AddrDstArr
		}

		for addrInx := 0; addrInx < len(addrArr); addrInx++ {
			if delSpecialCidr.First == addrArr[addrInx].CidrSpecial.First && delSpecialCidr.MaskSize == addrArr[addrInx].CidrSpecial.MaskSize {
				return false
			}
		}
	}

	return true
}

func getLpmKey(specialCidrPtr *SpecialCidr) LpmKeyV4 {

	key := LpmKeyV4{mask: specialCidrPtr.MaskSize, data: specialCidrPtr.First}

	return key
}

func (specialCidrPtr *SpecialCidr) standardCidr() string {
	ip := net.IPv4(specialCidrPtr.First[0], specialCidrPtr.First[1], specialCidrPtr.First[2], specialCidrPtr.First[3])

	return fmt.Sprintf("%s/%d", ip.String(), specialCidrPtr.MaskSize)
}
