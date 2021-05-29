## XDP-ACL RESTful API

[获取规则列表](#获取规则列表) 

[获取规则命中次数](#获取规则命中次数)

[添加规则](#添加规则)

[删除规则](#删除规则)

[获取eBPF map详情](#获取eBPF-Map详情)

----------------------------------

#### 获取规则列表

| 参数名称 | 参数说明 | 参数格式 |
| :-----: | :----: | :---- |
| strategy | 策略 | 1: 拒绝; 2: 允许 |
| protos | 协议类型 | 从右到左 二进制位分别表示 tcp, udp, icmp; 即 tcp: 0x01; tcp,udp: 0x03; all:0x07 |

* 请求方式 

  ```
  GET http://xdp-acl.com/xdp-acl/IPv4/rules
  ```

* 应答数据

  ```
  status: 200
  body:
  [
      {
          "priority": 33,
          "strategy": 1, // 1: 拒绝; 2: 允许
          "protos": 1, // bitmap 解析
          "addr_src_arr": [{
              "cidr_user": "4.3.2.1/28",
              "cidr_standard": "4.3.2.1/28"
          }],
          "port_src_arr": [
              80,
              8989
          ],
          "addr_dst_arr": [{
              "cidr_user": "4.3.2.1/28",
              "cidr_standard": "4.3.2.1/28"
          }],
          "port_dst_arr": [
              80,
              8989
          ],
          "hit_counts": "1000",
          "create_time": 1617020255000
      }
  ]
  ```

#### 获取规则命中次数

* 请求方式

  ```
  GET http://xdp-acl.com/xdp-acl/IPv4/rules/hitcount
  ```

* 应答数据

  ```
  status: 200
  body:
  [
      {
          "priority": 33,
          "hit_count": "1000"
      },
      {
          "priority": 34,
          "hit_count": "101"
      }
  ]
  ```

#### 添加规则

* 请求方式:

  ```
  POST http://xdp-acl.com/xdp-acl/IPv4/rule
  body:
  {
      "priority": 34,
      "strategy": 1,
      "protos": 1,
      "addr_src_arr": [{
          "cidr_user": "4.3.2.1/28",
      }],
      "port_src": [],
      "addr_dst_arr": [{
          "cidr_user": "4.3.2.1/28",
      }],
      "port_dst": [
          80
       ]
  }
  ```
* 应答数据:

  ```
  status: 201
  body:
  {
      "priority": 34,
      "create_time": 1617020255000,
      "addr_src_arr": [{
          "cidr_user": "4.3.2.1/28",
          "cidr_standard": "4.3.2.1/28"
      }],
      "addr_dst_arr": [{
          "cidr_user": "4.3.2.1/28",
          "cidr_standard": "4.3.2.1/28"
      }]
  }
  ```

#### 删除规则

* 请求方式

  ```
  DELETE http://xdp-acl.com/xdp-acl/IPv4/rule?priority=45
  ```

* 应答数据:

  ```
  status: 200
  body:
  {
    "priority": 34
  }
  ```

#### 获取eBPF map详情

| 参数名称 | 参数说明 | 参数类型 | 参数格式
| :-----: | :----: | :---- | :---- |
| name | eBPF map name | 路由参数| proto、rule_action、port_src、port_dst、ip_src、ip_dst|
| key | eBPF map key | 查询参数 | tcp/udp/icmp、1/2/3/4,5、 80/90、1.2.3.5/24 |
| filter | 是否被置位 | 查询参数 | unset、set、all |

* 示例一 请求方式

  ```
  GET http://xdp-acl.com/xdp-acl/IPv4/bpfmap/proto?key=tcp&filter=set
  ```

* 应答数据

  ```
  status: 200
  body:
  {
	  "time": "2021-05-27 00:46:51",
	  "set": {
	  	"size": 2,
	  	"arr": [100, 10239]
	  },
	  "unset": {}
  }
  ```

* 示例二 请求方式

  ```
  GET http://xdp-acl.com/xdp-acl/IPv4/bpfmap/rule_action?key=100,300
  ```

* 应答数据

  ```
  status: 200
  body:
  {
	  "time": "2021-05-27 01:27:48",
	  "size": 2,
  	"rule_action_arr": [{
	  	  "priority": 100,
	  	  "action": 2,
	  	  "hit_count": "0"
  	}, {
	  	  "priority": 300,
	  	  "action": 2,
	  	  "hit_count": "0"
  	}]
  }
  ```