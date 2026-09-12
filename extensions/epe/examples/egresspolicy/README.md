# EPE egresspolicy filter

`filter-config.json` 是 `egresspolicy` filter 的独立 JSON payload。filter、配置编译和调用方目标输入通道已实现。当前 SecurityProfile CRD 尚无对应 action，默认 wiring 不自动挂载；调用方通过 `egresspolicy.Definition()` 注册，并提供该名称对应的 payload。此文件不能作为 Kubernetes 资源直接部署。示例网段需替换为实际目的地址。

## 配置与运行时输入

策略配置只描述 CIDR、端口及动作。每次执行时，由调用方提供实际目标地址；目标不是静态策略配置的一部分。CONNECT 和普通 HTTP 使用相同的配置与输入契约。

调用方通过 `filter.Stream.Destination` 提供以下强类型字段；使用 extproc.Server 时由 resolver 返回 `engine.Resolution.Destination`，adapter 自动传递：

```go
type Destination struct {
    IP   netip.Addr
    Port uint16
}
```

对应的逻辑输入示例：

```json
{
  "destination": {
    "ip": "10.20.1.2",
    "port": 443
  }
}
```

此 JSON 仅展示运行时输入，不是新增的配置文件或已实现的 wire API。

- 调用方负责提取、解析和提供实际转发目标，并保证授权地址与实际连接地址一致。若路由、重试或地址解析使目标改变，调用方须对新目标重新执行检查后才能转发。
- filter 只读取 destination，不读取 method、authority、Host、scheme 或 Envoy 属性，不做 DNS 查询，也不根据请求协议选择地址来源。
- 输入必须包含有效 IP 和 1–65535 端口。缺失或非法输入直接拒绝，即使 defaultAction 为 allow；不尝试从其他字段补齐。
- IPv4-mapped IPv6 在匹配前统一为 IPv4；不接受 zone ID。配置中的 CIDR 与输入地址使用一致的规范化规则。
- 首版输入表示一个实际目标。域名及多个 DNS 候选地址由调用方处理，不能用一个已获准 IP 的判定放行另一个 IP。

## 匹配和执行语义

- EPE 在 request headers 阶段调用 filter，不读取或缓冲 body。
- rules 按声明顺序匹配，第一条命中的规则决定本 filter 的结果；没有命中则使用 defaultAction，省略时为 deny。
- action 和 defaultAction 仅支持 allow / deny。allow 返回 Continue，继续后续 filter 和 profile；deny 立即终止并返回 denyResponse，默认状态码 403。允许不代表 bypass。
- match.cidrs 支持 IPv4 / IPv6 CIDR，列表内部为 OR。单个 IP 使用 /32 或 /128。
- match.ports 是整数端口列表；match.portRanges 是闭区间列表。两者取并集，端口范围为 1–65535。
- CIDR 条件与端口条件之间为 AND。省略或空列表表示该维度不限；但规则的 match 必须至少包含一个非空限制，兜底统一用 defaultAction 表达。
- rules: [] 合法，完全使用默认动作。规则名必须非空且唯一；非法 CIDR、端口、倒置区间、未知字段或动作均在配置加载时拒绝，遵循现有 profile 保留最后有效版本的机制。
- 首版聚焦 CIDR、单端口和端口范围；调用方选择仍由外层 profile selector 负责。

## 调用方接入场景

| 场景 | 调用方提供 destination | 检查时机 |
| --- | --- | --- |
| Sandbox CONNECT | 从真实目标 authority（如 10.20.1.2:443 或 [fd00:20::1]:8443）解析 IP 和端口 | 建立隧道前一次 |
| 普通 HTTP | 从可信转发上下文取得实际目标 IP 和端口 | 每个请求转发前，即使复用已有连接 |

Sandbox CONNECT 接入层严格解析 authority 中的 IP 与显式端口，不用网关监听地址覆盖。普通 HTTP 接入层负责在授权前取得实际目标信息；HTTP Host 可以是域名，不要求改为 IP，只要接入层能提供实际目标。两条路径最终都填充相同的 destination，filter 无协议分支。

CONNECT 通过其余适用 filter 后由网关建立隧道；拒绝时在建立隧道前返回 403，不向目标转发隧道数据。一次允许覆盖该 CONNECT 流内的所有后续请求，filter 不解析内部 HTTP、TLS 或其他字节。策略更新作用于新的 CONNECT，首版不主动断开或重新授权已有隧道。普通 HTTP 则每个请求使用当时生效的策略检查。

现有 attributes.Extract 的 HTTP 字段提取行为保持不变。统一 destination 由 resolver 返回，不从这些 HTTP 字段自动推断；默认 SecurityProfile resolver 不提供 destination。使用方须在自己的 resolver 中接入真实目标，并确保普通 HTTP 在授权阶段可取得实际目标。

该 filter 仅约束进入 EPE 且被选中执行的请求。规则内部的默认拒绝不改变外层 profile 未匹配、先前 bypass 或缺失 peer 身份时的现有行为。

## 示例结果

以下结果对 CONNECT 和普通 HTTP 完全相同：

| 调用方传入的目标 | 结果 |
| --- | --- |
| 169.254.169.254:443 | deny-metadata，拒绝 |
| 10.20.1.2:443 | allow-internal-https，继续后续 filter |
| [fd00:20::1]:8443 | allow-internal-https，继续后续 filter |
| 10.20.1.2:80 | defaultAction，拒绝 |
| 10.30.1.2:8050 | allow-internal-services，继续后续 filter |
| 10.30.1.2:8100 | defaultAction，拒绝 |
| 缺少 IP 或 port=0 | 输入无效，拒绝 |

自动化测试覆盖独立配置编译、IPv4/IPv6/映射地址、端口范围边界、有序规则、无效输入拒绝，以及经真实 extproc.Server 处理 CONNECT/GET/POST 时的允许、拒绝和继续执行后续 filter。测试使用脚本化 Envoy 消息，不包含真实网关连接、隧道内部流量或在线策略更新验证。

## 调用方接入

```go
regs, err := filter.Build(egresspolicy.Definition())
// 检查 err；多 filter 场景将它放在 body 检查和凭证转换之前。
cfgs, projectionErrors := filter.Project(regs, map[string]json.RawMessage{
    egresspolicy.FilterName: payload,
})
// 检查每个 projectionErrors，只有全部成功才安装配置。

// resolver 在每次请求上返回编译好的 units 与实际目标。
return engine.Resolution{
    Destination: filter.Destination{IP: actualIP, Port: actualPort},
    Units: []engine.Unit{{
        ID: filter.UnitID{Scope: "caller", Name: "egress"},
        Cfgs: cfgs,
    }},
}, nil
```

将同一组 regs 传入 extproc.ServerDeps.Registrations。直接调用 engine 的使用方则填充 filter.Stream.Destination。配置只需编译一次，可在请求间复用；每个请求传入自己的目标地址。外层 resolver 必须为需要管控的每个请求返回该 unit；不返回 unit 仍表示没有适用策略。
