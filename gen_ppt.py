"""Generate HideWG project presentation with focus on encapsulation strategy."""

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

# ── Color Palette ──
BG_DARK   = RGBColor(0x1A, 0x1A, 0x2E)  # dark navy
BG_MID    = RGBColor(0x16, 0x21, 0x3E)  # mid navy
ACCENT    = RGBColor(0x00, 0xD2, 0xFF)  # cyan
ACCENT2   = RGBColor(0xFF, 0x6B, 0x6B)  # coral
ACCENT3   = RGBColor(0x4E, 0xC9, 0xB0)  # teal
WHITE     = RGBColor(0xFF, 0xFF, 0xFF)
GRAY      = RGBColor(0xAA, 0xAA, 0xBB)
YELLOW    = RGBColor(0xFF, 0xD9, 0x3D)
GREEN     = RGBColor(0x4E, 0xC9, 0xB0)
RED       = RGBColor(0xFF, 0x6B, 0x6B)

prs = Presentation()
prs.slide_width  = Inches(13.333)
prs.slide_height = Inches(7.5)
W = prs.slide_width
H = prs.slide_height

# ── Helpers ──

def set_bg(slide, color):
    bg = slide.background
    fill = bg.fill
    fill.solid()
    fill.fore_color.rgb = color

def add_rect(slide, left, top, width, height, fill_color, border_color=None):
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill_color
    if border_color:
        shape.line.color.rgb = border_color
        shape.line.width = Pt(1.5)
    else:
        shape.line.fill.background()
    return shape

def add_text(slide, left, top, width, height, text, size=18, color=WHITE, bold=False, align=PP_ALIGN.LEFT, font_name="Consolas"):
    txBox = slide.shapes.add_textbox(left, top, width, height)
    tf = txBox.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = text
    p.font.size = Pt(size)
    p.font.color.rgb = color
    p.font.bold = bold
    p.font.name = font_name
    p.alignment = align
    return txBox

def add_multiline(slide, left, top, width, height, lines, size=16, color=WHITE, line_spacing=1.3, font_name="Consolas"):
    """lines: list of (text, color, bold, size_override)"""
    txBox = slide.shapes.add_textbox(left, top, width, height)
    tf = txBox.text_frame
    tf.word_wrap = True
    for i, item in enumerate(lines):
        if isinstance(item, str):
            txt, clr, bld, sz = item, color, False, size
        else:
            txt = item[0]
            clr = item[1] if len(item) > 1 else color
            bld = item[2] if len(item) > 2 else False
            sz  = item[3] if len(item) > 3 else size
        if i == 0:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()
        p.text = txt
        p.font.size = Pt(sz)
        p.font.color.rgb = clr
        p.font.bold = bld
        p.font.name = font_name
        p.space_after = Pt(sz * 0.3)
    return txBox

def add_bullet_list(slide, left, top, width, height, items, size=16, color=WHITE, bullet_color=ACCENT, font_name="Consolas"):
    txBox = slide.shapes.add_textbox(left, top, width, height)
    tf = txBox.text_frame
    tf.word_wrap = True
    for i, item in enumerate(items):
        if isinstance(item, str):
            txt, clr = item, color
        else:
            txt, clr = item[0], item[1] if len(item) > 1 else color
        if i == 0:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()
        p.text = txt
        p.font.size = Pt(size)
        p.font.color.rgb = clr
        p.font.name = font_name
        p.space_after = Pt(4)
    return txBox

def add_arrow(slide, x1, y1, x2, y2, color=ACCENT, width=Pt(2)):
    connector = slide.shapes.add_connector(1, x1, y1, x2, y2)  # 1 = straight
    connector.line.color.rgb = color
    connector.line.width = width
    return connector


# ════════════════════════════════════════════════════════════════════
# SLIDE 1 — Title
# ════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])  # blank
set_bg(sl, BG_DARK)

# Decorative top bar
add_rect(sl, Inches(0), Inches(0), W, Inches(0.06), ACCENT)

add_text(sl, Inches(1), Inches(1.5), Inches(11), Inches(1.2),
         "HideWG", size=60, color=ACCENT, bold=True)
add_text(sl, Inches(1), Inches(2.7), Inches(11), Inches(0.8),
         "WireGuard 流量隐蔽隧道系统", size=32, color=WHITE, bold=True)
add_text(sl, Inches(1), Inches(3.8), Inches(11), Inches(0.6),
         "基于 WebSocket + TLS 的多层封装策略", size=22, color=GRAY)

# Decorative line
add_rect(sl, Inches(1), Inches(4.6), Inches(3), Inches(0.04), ACCENT)

add_text(sl, Inches(1), Inches(5.2), Inches(11), Inches(0.5),
         "让 VPN 流量看起来像正常的 HTTPS 网页浏览", size=18, color=GRAY)
add_text(sl, Inches(1), Inches(6.3), Inches(11), Inches(0.4),
         "Python  |  ChaCha20-Poly1305  |  RFC 6455 WebSocket  |  TLS 1.3", size=14, color=GRAY)


# ════════════════════════════════════════════════════════════════════
# SLIDE 2 — Problem Statement
# ════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
set_bg(sl, BG_DARK)
add_rect(sl, Inches(0), Inches(0), W, Inches(0.06), ACCENT)

add_text(sl, Inches(0.8), Inches(0.4), Inches(5), Inches(0.6),
         "01  问题背景", size=28, color=ACCENT, bold=True)

# Left: WireGuard problem
add_rect(sl, Inches(0.8), Inches(1.3), Inches(5.5), Inches(5.5), BG_MID, ACCENT2)
add_text(sl, Inches(1.1), Inches(1.5), Inches(5), Inches(0.5),
         "WireGuard 的流量特征", size=20, color=ACCENT2, bold=True)
add_bullet_list(sl, Inches(1.1), Inches(2.2), Inches(5), Inches(4.2), [
    ("  固定首字节: 0x01/0x02/0x03/0x04 (消息类型)", WHITE),
    ("  保留零字节: 每包固定位置全零", WHITE),
    ("  固定包长: 148B 握手发起 + 92B 响应", WHITE),
    ("  Keepalive 模式: 固定间隔空包", WHITE),
    ("  协议指纹: UDP + 特定端口 + 熵值特征", WHITE),
    ("", WHITE),
    ("  => 被 DPI 规则命中率 62.5%", ACCENT2),
    ("  => ML 分类器准确率 100%", ACCENT2),
], size=15)

# Right: Goal
add_rect(sl, Inches(7), Inches(1.3), Inches(5.5), Inches(5.5), BG_MID, ACCENT3)
add_text(sl, Inches(7.3), Inches(1.5), Inches(5), Inches(0.5),
         "HideWG 目标", size=20, color=ACCENT3, bold=True)
add_bullet_list(sl, Inches(7.3), Inches(2.2), Inches(5), Inches(4.2), [
    ("  消除所有 WireGuard 固定字节特征", WHITE),
    ("  伪装为标准 HTTPS WebSocket 流量", WHITE),
    ("  模拟真实网页浏览的包长/时序分布", WHITE),
    ("  对抗规则检测 + ML 分类器", WHITE),
    ("  兼容现有 WireGuard 基础设施", WHITE),
    ("", WHITE),
    ("  => 规则命中率降至 20%", ACCENT3),
    ("  => 所有功能测试 8/8 通过", ACCENT3),
], size=15)


# ════════════════════════════════════════════════════════════════════
# SLIDE 3 — Architecture Overview
# ════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
set_bg(sl, BG_DARK)
add_rect(sl, Inches(0), Inches(0), W, Inches(0.06), ACCENT)

add_text(sl, Inches(0.8), Inches(0.4), Inches(5), Inches(0.6),
         "02  系统架构总览", size=28, color=ACCENT, bold=True)

# Encapsulation layers diagram
layers = [
    ("WireGuard UDP 包",      ACCENT2,  "内部原始 VPN 负载"),
    ("HideWG Codec",          ACCENT,   "分片 + 填充 + ChaCha20-Poly1305 AEAD 加密"),
    ("Noise Injection",       YELLOW,   "S4 前缀填充 + 噪声前缀 + 垃圾包注入"),
    ("WebSocket Binary Frame", ACCENT3,  "RFC 6455 二进制帧 + 掩码"),
    ("TLS 1.3",               RGBColor(0xBB, 0x86, 0xFC), "标准 HTTPS 加密层"),
    ("TCP/IP :443",           GRAY,     "与普通网页浏览完全一致"),
]

box_w = Inches(10)
box_h = Inches(0.72)
start_x = Inches(1.6)
start_y = Inches(1.3)
gap = Inches(0.12)

for i, (name, color, desc) in enumerate(layers):
    y = start_y + i * (box_h + gap)
    # Layer box
    add_rect(sl, start_x, y, box_w, box_h, BG_MID, color)
    # Layer name
    add_text(sl, start_x + Inches(0.3), y + Inches(0.08), Inches(3.5), box_h,
             name, size=18, color=color, bold=True)
    # Description
    add_text(sl, start_x + Inches(4), y + Inches(0.08), Inches(5.5), box_h,
             desc, size=14, color=GRAY)
    # Arrow between layers
    if i < len(layers) - 1:
        arrow_y = y + box_h
        add_text(sl, start_x + Inches(4.5), arrow_y - Inches(0.05), Inches(1), Inches(0.2),
                 "", size=10, color=color)

# Side label
add_text(sl, Inches(0.3), Inches(2.5), Inches(1.2), Inches(2),
         "外\n层\n封\n装", size=16, color=ACCENT, bold=True)
add_text(sl, Inches(0.3), Inches(1.3), Inches(1.2), Inches(1),
         "内层", size=16, color=ACCENT2, bold=True)


# ════════════════════════════════════════════════════════════════════
# SLIDE 4 — Layer 1: HideWG Protocol Codec (Detailed)
# ════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
set_bg(sl, BG_DARK)
add_rect(sl, Inches(0), Inches(0), W, Inches(0.06), ACCENT)

add_text(sl, Inches(0.8), Inches(0.4), Inches(8), Inches(0.6),
         "03  封装策略 (一): HideWG 协议编解码", size=28, color=ACCENT, bold=True)

# Left: Header structure
add_rect(sl, Inches(0.8), Inches(1.3), Inches(5.8), Inches(5.8), BG_MID, ACCENT)
add_text(sl, Inches(1.1), Inches(1.5), Inches(5.4), Inches(0.5),
         "协议头 HEADER (24 字节)", size=18, color=ACCENT, bold=True)

header_lines = [
    ("  Byte  0     : version      (B, 1字节)  固定值 1", WHITE),
    ("  Byte  1     : flags        (B, 1字节)  FLAG_FRAGMENTED=0x01", WHITE),
    ("  Byte  2-5   : session_id   (I, 4字节)  会话标识", WHITE),
    ("  Byte  6-13  : sequence     (Q, 8字节)  单调递增序列号", WHITE),
    ("  Byte 14-17  : message_id   (I, 4字节)  消息分组ID", WHITE),
    ("  Byte 18-19  : fragment_index (H, 2字节) 分片序号", WHITE),
    ("  Byte 20-21  : fragment_count (H, 2字节) 总分片数", WHITE),
    ("  Byte 22-23  : payload_len  (H, 2字节)  原始负载长度", WHITE),
    ("  Byte 24-25  : padding_len  (H, 2字节)  填充长度", WHITE),
    ("", WHITE),
    ("  加密: ChaCha20-Poly1305 (AEAD)", ACCENT),
    ("  密钥: SHA-256(\"hidewg-v1:\" + secret)", ACCENT),
    ("  每记录: [12B nonce][ciphertext][16B tag]", ACCENT),
]
add_multiline(sl, Inches(1.1), Inches(2.1), Inches(5.4), Inches(4.8), header_lines, size=13)

# Right: AEAD encryption diagram
add_rect(sl, Inches(7), Inches(1.3), Inches(5.8), Inches(2.6), BG_MID, ACCENT3)
add_text(sl, Inches(7.3), Inches(1.5), Inches(5.4), Inches(0.5),
         "AEAD 加密封装", size=18, color=ACCENT3, bold=True)
add_multiline(sl, Inches(7.3), Inches(2.1), Inches(5.2), Inches(1.5), [
    ("明文 = header(24B) + body(负载+填充)", WHITE),
    ("nonce = os.urandom(12)  (每记录随机)", WHITE),
    ("密文 = ChaCha20Poly1305.encrypt(nonce,明文)", WHITE),
    ("输出 = nonce(12B) + 密文 + tag(16B)", ACCENT3),
], size=14)

# Right bottom: Key purpose
add_rect(sl, Inches(7), Inches(4.2), Inches(5.8), Inches(2.9), BG_MID, YELLOW)
add_text(sl, Inches(7.3), Inches(4.4), Inches(5.4), Inches(0.5),
         "消除的 WireGuard 特征", size=18, color=YELLOW, bold=True)
add_multiline(sl, Inches(7.3), Inches(5.0), Inches(5.2), Inches(1.8), [
    ("  R1: 首字节 0x01-0x04  => 全部加密消除  100%->0%", GREEN),
    ("  R2: 保留零字节        => 加密后不可见", GREEN),
    ("  R3: 典型包长 148/92B  => 填充后随机化  12.5%->0%", GREEN),
    ("  R5: 固定 Keepalive    => 噪声注入消除  100%->0%", GREEN),
], size=14)


# ════════════════════════════════════════════════════════════════════
# SLIDE 5 — Fragmentation Strategy
# ════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
set_bg(sl, BG_DARK)
add_rect(sl, Inches(0), Inches(0), W, Inches(0.06), ACCENT)

add_text(sl, Inches(0.8), Inches(0.4), Inches(8), Inches(0.6),
         "04  封装策略 (二): 随机分片", size=28, color=ACCENT, bold=True)

# Left: How it works
add_rect(sl, Inches(0.8), Inches(1.3), Inches(5.8), Inches(5.8), BG_MID, ACCENT)
add_text(sl, Inches(1.1), Inches(1.5), Inches(5.4), Inches(0.5),
         "_random_split() 算法", size=18, color=ACCENT, bold=True)
add_multiline(sl, Inches(1.1), Inches(2.2), Inches(5.4), Inches(4.5), [
    ("触发条件: 包长 > max_fragment_payload (默认1300B)", WHITE),
    ("", WHITE),
    ("分片流程:", ACCENT),
    ("  while 还有剩余数据:", WHITE),
    ("    size = random.randint(434, 1300)", YELLOW),
    ("    取出 size 字节作为一个分片", WHITE),
    ("    每个分片独立 AEAD 加密", WHITE),
    ("  最后一个分片持有剩余 (可能 < 434B)", WHITE),
    ("", WHITE),
    ("关键设计:", ACCENT),
    ("  - 分片大小随机, 打破等长包模式", GREEN),
    ("  - 共享 message_id, 接收端按序重组", GREEN),
    ("  - FLAG_FRAGMENTED 标记多分片消息", GREEN),
    ("  - 序列号单调递增, 防重放攻击", GREEN),
], size=14)

# Right: Why random fragments
add_rect(sl, Inches(7), Inches(1.3), Inches(5.8), Inches(3.2), BG_MID, ACCENT2)
add_text(sl, Inches(7.3), Inches(1.5), Inches(5.4), Inches(0.5),
         "为什么需要随机分片?", size=18, color=ACCENT2, bold=True)
add_multiline(sl, Inches(7.3), Inches(2.2), Inches(5.2), Inches(2.0), [
    ("CNN 分类器依赖的特征:", WHITE),
    ("  - 连续等长包的自相关性 (lag autocorrelation)", WHITE),
    ("  - 固定分片边界产生的包长直方图峰值", WHITE),
    ("", WHITE),
    ("随机分片效果:", ACCENT3),
    ("  每个分片长度在 [434, 1300] 均匀分布", ACCENT3),
    ("  连续包长无规律, 自相关特征被破坏", ACCENT3),
], size=14)

# Right bottom: Reassembly
add_rect(sl, Inches(7), Inches(4.8), Inches(5.8), Inches(2.3), BG_MID, YELLOW)
add_text(sl, Inches(7.3), Inches(5.0), Inches(5.4), Inches(0.5),
         "重组器 Reassembler", size=18, color=YELLOW, bold=True)
add_multiline(sl, Inches(7.3), Inches(5.6), Inches(5.2), Inches(1.2), [
    ("  滑动窗口: 4096 序列号 (防重放)", WHITE),
    ("  分片 TTL: 30 秒超时丢弃", WHITE),
    ("  索引: (session_id, message_id)", WHITE),
    ("  重复检测: 相同序列号直接丢弃", WHITE),
], size=14)


# ════════════════════════════════════════════════════════════════════
# SLIDE 6 — Padding Policies
# ════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
set_bg(sl, BG_DARK)
add_rect(sl, Inches(0), Inches(0), W, Inches(0.06), ACCENT)

add_text(sl, Inches(0.8), Inches(0.4), Inches(8), Inches(0.6),
         "05  封装策略 (三): 四种填充策略", size=28, color=ACCENT, bold=True)

# 2x2 grid
policies = [
    ("Fixed-Bucket (默认)", ACCENT, [
        "桶: [96, 128, 192, 256, 384, 512, 768, 1024, 1280]",
        "选择最小能容纳负载的桶",
        "20% 概率提升到下一个桶 (抖动)",
        "每32包桶边界随机漂移 +/-N",
        "",
        "效果: 打破精确尺寸聚类",
    ]),
    ("Adaptive (自适应)", ACCENT3, [
        "维护 128 包滑动窗口历史",
        "60% 概率选择低频桶 (分布均匀化)",
        "高斯抖动: gauss(0, 15) 打破桶对齐",
        "权重 = (期望+1)/(计数+1) x 1.5倍自然桶",
        "",
        "效果: 对抗 RF 直方图分箱特征",
    ]),
    ("Traffic Mimicry (流量模拟)", YELLOW, [
        "模拟真实 HTTPS 包长分布:",
        "  60B (ACK, 15%) / 200B (API, 5%)",
        "  500B (数据, 5%) / 1400B (MSS, 75%)",
        "预计算 ~60 个真实包长, 4B对齐",
        "",
        "效果: 唯一包长数匹配真实HTTPS (~70)",
    ]),
    ("Continuous (连续分布)", ACCENT2, [
        "多模态连续分布模拟UDP混合流量:",
        "  25% gauss(85,30) ACK/DNS",
        "  30% gauss(900,300) QUIC",
        "  20% gauss(200,80) 游戏",
        "  15% gauss(120,40) VoIP",
        "每64包随机重塑分布形状",
    ]),
]

for idx, (title, color, lines) in enumerate(policies):
    col = idx % 2
    row = idx // 2
    x = Inches(0.8) + col * Inches(6.2)
    y = Inches(1.3) + row * Inches(3.1)
    add_rect(sl, x, y, Inches(5.8), Inches(2.9), BG_MID, color)
    add_text(sl, x + Inches(0.3), y + Inches(0.15), Inches(5.2), Inches(0.4),
             title, size=16, color=color, bold=True)
    add_multiline(sl, x + Inches(0.3), y + Inches(0.6), Inches(5.2), Inches(2.2),
                  [(l, WHITE if not l.startswith("效果") else GREEN) for l in lines],
                  size=12)


# ════════════════════════════════════════════════════════════════════
# SLIDE 7 — Noise Injection
# ════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
set_bg(sl, BG_DARK)
add_rect(sl, Inches(0), Inches(0), W, Inches(0.06), ACCENT)

add_text(sl, Inches(0.8), Inches(0.4), Inches(8), Inches(0.6),
         "06  封装策略 (四): 噪声注入", size=28, color=ACCENT, bold=True)

# S4 + Noise Prefix
add_rect(sl, Inches(0.8), Inches(1.3), Inches(7.5), Inches(3), BG_MID, ACCENT)
add_text(sl, Inches(1.1), Inches(1.5), Inches(7), Inches(0.5),
         "S4 前缀填充 + 噪声前缀 (AmneziaWG 灵感)", size=18, color=ACCENT, bold=True)

add_multiline(sl, Inches(1.1), Inches(2.2), Inches(7), Inches(1.8), [
    ("外层数据格式:", ACCENT),
    ("  [1B: s4_len] [s4_len 随机字节] [1B: noise_len] [noise_len 随机字节] [HideWG 记录]", YELLOW),
    ("", WHITE),
    ("S4 填充: 0~48 字节随机长度 (s4_padding_max=48)", WHITE),
    ("噪声前缀: 0~24 字节随机长度 (noise_prefix_range=(0,24))", WHITE),
    ("接收端: 用两个 1B 长度指示器确定性剥离", GREEN),
    ("效果: 即使填充到桶 256, 实际线上包长也会随机偏移", GREEN),
], size=14)

# Junk packets
add_rect(sl, Inches(0.8), Inches(4.6), Inches(3.5), Inches(2.5), BG_MID, YELLOW)
add_text(sl, Inches(1.1), Inches(4.8), Inches(3.1), Inches(0.4),
         "垃圾包注入", size=18, color=YELLOW, bold=True)
add_multiline(sl, Inches(1.1), Inches(5.3), Inches(3.1), Inches(1.5), [
    ("会话开始前发送 3 个随机包", WHITE),
    ("大小: 64~384 字节随机", WHITE),
    ("", WHITE),
    ("消除 WG 握手模式:", GREEN),
    ("  148B Initiation + 92B Response", GREEN),
], size=13)

# Cover traffic
add_rect(sl, Inches(4.6), Inches(4.6), Inches(7.9), Inches(2.5), BG_MID, ACCENT3)
add_text(sl, Inches(4.9), Inches(4.8), Inches(7.5), Inches(0.4),
         "覆盖流量 (Cover Traffic)", size=18, color=ACCENT3, bold=True)
add_multiline(sl, Inches(4.9), Inches(5.3), Inches(7.5), Inches(1.5), [
    ("空闲期间持续发送仿真流量, 模拟真实 HTTPS 模式:", WHITE),
    ("  突发模型: 突发间隔 100-800ms, 突发内间隔 1-10ms", WHITE),
    ("  角色感知: 客户端小包(60-200B), 服务端大包(1200-1400B)", WHITE),
    ("  方向比 ~0.25 (客户端:服务端字节数), 匹配真实 HTTPS", WHITE),
    ("  双方可区分: SHAKE-256(cover_key + nonce) 确定性生成", GREEN),
], size=13)


# ════════════════════════════════════════════════════════════════════
# SLIDE 8 — WebSocket + TLS + HTTP Mux
# ════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
set_bg(sl, BG_DARK)
add_rect(sl, Inches(0), Inches(0), W, Inches(0.06), ACCENT)

add_text(sl, Inches(0.8), Inches(0.4), Inches(10), Inches(0.6),
         "07  封装策略 (五): WebSocket + TLS + HTTP 伪装", size=28, color=ACCENT, bold=True)

# WebSocket
add_rect(sl, Inches(0.8), Inches(1.3), Inches(3.7), Inches(3), BG_MID, ACCENT3)
add_text(sl, Inches(1.1), Inches(1.5), Inches(3.3), Inches(0.4),
         "WebSocket 帧封装", size=16, color=ACCENT3, bold=True)
add_multiline(sl, Inches(1.1), Inches(2.0), Inches(3.3), Inches(2.0), [
    ("RFC 6455 二进制帧:", WHITE),
    ("  FIN=1, opcode=0x02", WHITE),
    ("  客户端: 掩码 (4B key XOR)", WHITE),
    ("  服务端: 无掩码", WHITE),
    ("", WHITE),
    ("握手伪装:", GREEN),
    ("  User-Agent: Mozilla/5.0...", GREEN),
    ("  Protocol: chat", GREEN),
], size=13)

# TLS
add_rect(sl, Inches(4.8), Inches(1.3), Inches(3.7), Inches(3), BG_MID, RGBColor(0xBB, 0x86, 0xFC))
add_text(sl, Inches(5.1), Inches(1.5), Inches(3.3), Inches(0.4),
         "TLS 1.3 加密", size=16, color=RGBColor(0xBB, 0x86, 0xFC), bold=True)
add_multiline(sl, Inches(5.1), Inches(2.0), Inches(3.3), Inches(2.0), [
    ("标准 TLS 握手:", WHITE),
    ("  RSA 2048 / SHA-256", WHITE),
    ("  自签名或 Let's Encrypt", WHITE),
    ("", WHITE),
    ("传输层封装:", WHITE),
    ("  2B 长度前缀 + WS帧", WHITE),
    ("  全部在 TLS 记录内", WHITE),
], size=13)

# HTTP Mux
add_rect(sl, Inches(8.8), Inches(1.3), Inches(3.7), Inches(3), BG_MID, YELLOW)
add_text(sl, Inches(9.1), Inches(1.5), Inches(3.3), Inches(0.4),
         "HTTP 多路复用器", size=16, color=YELLOW, bold=True)
add_multiline(sl, Inches(9.1), Inches(2.0), Inches(3.3), Inches(2.0), [
    ("自动检测连接类型:", WHITE),
    ("  TLS ClientHello? => TLS", WHITE),
    ("  WS Upgrade? => WebSocket", WHITE),
    ("  HTTP GET? => 假网页", WHITE),
    ("", WHITE),
    ("伪装身份:", GREEN),
    ("  Apache/2.4.58 (Unix)", GREEN),
    ('  "It works!" 默认页', GREEN),
], size=13)

# nginx deployment
add_rect(sl, Inches(0.8), Inches(4.6), Inches(11.7), Inches(2.5), BG_MID, ACCENT2)
add_text(sl, Inches(1.1), Inches(4.8), Inches(11.3), Inches(0.4),
         "生产部署: nginx 反向代理", size=18, color=ACCENT2, bold=True)

add_multiline(sl, Inches(1.1), Inches(5.4), Inches(5), Inches(1.4), [
    ("数据流:", ACCENT),
    ("  客户端 --WSS(TLS1.3)--> nginx:443", WHITE),
    ("  nginx --WS(明文)--> HideWG:8443", WHITE),
], size=14)

add_multiline(sl, Inches(6.5), Inches(5.4), Inches(5.5), Inches(1.4), [
    ("nginx 职责:", ACCENT),
    ("  TLS 终结 (Let's Encrypt 证书)", WHITE),
    ("  WebSocket 头转发", WHITE),
    ("  非 WS 请求返回正常网站", WHITE),
], size=14)


# ════════════════════════════════════════════════════════════════════
# SLIDE 9 — Complete Data Path
# ════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
set_bg(sl, BG_DARK)
add_rect(sl, Inches(0), Inches(0), W, Inches(0.06), ACCENT)

add_text(sl, Inches(0.8), Inches(0.4), Inches(10), Inches(0.6),
         "08  完整数据路径", size=28, color=ACCENT, bold=True)

# Encode path
add_rect(sl, Inches(0.8), Inches(1.2), Inches(5.8), Inches(5.8), BG_MID, ACCENT)
add_text(sl, Inches(1.1), Inches(1.4), Inches(5.4), Inches(0.4),
         "发送方向 (Encode)", size=18, color=ACCENT, bold=True)

encode_steps = [
    ("1. WireGuard 产出加密 UDP 包 (如 128B)", WHITE),
    ("2. _random_split() 随机分片 [434,1300]B", YELLOW),
    ("3. PaddingPolicy 填充到目标长度", YELLOW),
    ("4. 24B header + 填充后 body", WHITE),
    ("5. ChaCha20-Poly1305 AEAD 加密", ACCENT),
    ("6. S4前缀 + 噪声前缀 包装", ACCENT3),
    ("7. WebSocket 二进制帧 + 掩码", ACCENT3),
    ("8. TLS 1.3 加密传输", RGBColor(0xBB,0x86,0xFC)),
    ("9. TCP/IP :443 (标准 HTTPS)", GRAY),
    ("10.空闲时注入覆盖流量", GREEN),
]
add_multiline(sl, Inches(1.1), Inches(2.0), Inches(5.4), Inches(4.5), encode_steps, size=14)

# Decode path
add_rect(sl, Inches(7), Inches(1.2), Inches(5.8), Inches(5.8), BG_MID, ACCENT3)
add_text(sl, Inches(7.3), Inches(1.4), Inches(5.4), Inches(0.4),
         "接收方向 (Decode)", size=18, color=ACCENT3, bold=True)

decode_steps = [
    ("1. TCP/IP 收到 TLS 记录", GRAY),
    ("2. TLS 解密得到原始字节", RGBColor(0xBB,0x86,0xFC)),
    ("3. WebSocket 帧解码 (去掩码)", ACCENT3),
    ("4. strip_noise() 剥离 S4 + 噪声", ACCENT3),
    ("5. ChaCha20-Poly1305 解密 + 验证", ACCENT),
    ("6. 解析 header: session/seq/fragment", WHITE),
    ("7. Reassembler 重组 (按 message_id)", YELLOW),
    ("8. 重放检测 (序列号滑动窗口)", YELLOW),
    ("9. 还原原始 WireGuard UDP 包", WHITE),
    ("10.转发给内部 WireGuard 接口", WHITE),
]
add_multiline(sl, Inches(7.3), Inches(2.0), Inches(5.4), Inches(4.5), decode_steps, size=14)


# ════════════════════════════════════════════════════════════════════
# SLIDE 10 — Anti-Detection Summary
# ════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
set_bg(sl, BG_DARK)
add_rect(sl, Inches(0), Inches(0), W, Inches(0.06), ACCENT)

add_text(sl, Inches(0.8), Inches(0.4), Inches(10), Inches(0.6),
         "09  反检测能力总结", size=28, color=ACCENT, bold=True)

# Table-like layout
features = [
    ("检测维度",          "原始 WireGuard", "HideWG", "对抗手段"),
    ("R1 首字节消息类型",  "100% 命中",      "0%",    "AEAD 加密消除"),
    ("R2 保留零字节",      "100% 命中",      "100%",  "未处理 (待优化)"),
    ("R3 典型包长",        "12.5% 命中",     "0%",    "填充策略随机化"),
    ("R4 握手方向时序",    "0% 命中",        "0%",    "覆盖流量掩盖"),
    ("R5 固定 Keepalive",  "100% 命中",      "0%",    "噪声注入消除"),
    ("总规则命中率",       "62.5%",          "20%",   "降低 42.5 个百分点"),
    ("ML 分类器",         "可检测",          "不可检测", "分片+填充+噪声"),
]

y_start = Inches(1.3)
row_h = Inches(0.6)
col_widths = [Inches(3), Inches(2.5), Inches(2), Inches(4)]
col_starts = [Inches(0.8)]
for w in col_widths[:-1]:
    col_starts.append(col_starts[-1] + w)

for i, row in enumerate(features):
    y = y_start + i * row_h
    bg_color = BG_MID if i % 2 == 1 else RGBColor(0x20, 0x2A, 0x44)
    is_header = i == 0
    add_rect(sl, Inches(0.8), y, Inches(11.5), row_h, bg_color)
    for j, cell in enumerate(row):
        clr = ACCENT if is_header else (GREEN if "0%" == cell or "不可检测" in cell else (RED if "100%" in cell and i > 0 and i != 6 else WHITE))
        if i == 6:  # summary row
            clr = YELLOW
        add_text(sl, col_starts[j], y + Inches(0.1), col_widths[j], row_h,
                 cell, size=13, color=clr, bold=is_header or i == 6)


# ════════════════════════════════════════════════════════════════════
# SLIDE 11 — Performance Results
# ════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
set_bg(sl, BG_DARK)
add_rect(sl, Inches(0), Inches(0), W, Inches(0.06), ACCENT)

add_text(sl, Inches(0.8), Inches(0.4), Inches(10), Inches(0.6),
         "10  性能测试结果", size=28, color=ACCENT, bold=True)

# Metrics cards
metrics = [
    ("功能测试", "8/8 通过", GREEN, "全部正确"),
    ("吞吐保留率", "2.3%", RED, "CPU 处理瓶颈"),
    ("带宽膨胀", "1.38x", YELLOW, "封装+填充开销"),
    ("延迟增加", "0.09 ms", GREEN, "每包极低"),
    ("CPU 开销", "273%", RED, "Python 热路径"),
    ("内存峰值", "31.9 KB", GREEN, "极低"),
]

for i, (name, value, color, note) in enumerate(metrics):
    col = i % 3
    row = i // 3
    x = Inches(0.8) + col * Inches(4.1)
    y = Inches(1.3) + row * Inches(2.5)
    add_rect(sl, x, y, Inches(3.7), Inches(2.2), BG_MID, color)
    add_text(sl, x + Inches(0.3), y + Inches(0.2), Inches(3.1), Inches(0.4),
             name, size=16, color=GRAY)
    add_text(sl, x + Inches(0.3), y + Inches(0.7), Inches(3.1), Inches(0.7),
             value, size=36, color=color, bold=True)
    add_text(sl, x + Inches(0.3), y + Inches(1.5), Inches(3.1), Inches(0.4),
             note, size=14, color=GRAY)

# Loss tolerance
add_rect(sl, Inches(0.8), Inches(6.5), Inches(11.7), Inches(0.7), BG_MID, ACCENT3)
add_text(sl, Inches(1.1), Inches(6.55), Inches(11), Inches(0.5),
         "丢包容忍: 1%丢包->98.5%完成  |  3%丢包->96.5%完成  |  5%丢包->91.5%完成",
         size=15, color=ACCENT3)


# ════════════════════════════════════════════════════════════════════
# SLIDE 12 — Performance Bottleneck Analysis
# ════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
set_bg(sl, BG_DARK)
add_rect(sl, Inches(0), Inches(0), W, Inches(0.06), ACCENT)

add_text(sl, Inches(0.8), Inches(0.4), Inches(10), Inches(0.6),
         "11  性能瓶颈分析", size=28, color=ACCENT, bold=True)

bottlenecks = [
    ("WS mask/unmask 逐字节 Python 循环", "最大瓶颈", RED,
     "ws.py:52-55 — 每分片 ~1400 次 Python 迭代\n273 分片 = 38 万次 XOR 字节码执行\n可用 C 扩展或 numpy 向量化提升 50-100x"),
    ("每分片 2 次 os.urandom() 系统调用", "高", ACCENT2,
     "protocol.py:311,324 — 填充字节 + nonce\n273 x 2 = 546 次内核态切换\n可批量预生成随机字节池"),
    ("每分片独立 AEAD 加解密", "中", YELLOW,
     "protocol.py:327,347 — ChaCha20-Poly1305\n273 x 2 = 546 次 Python-C FFI 调用\n可合并小分片减少调用次数"),
    ("大量 bytes() 内存拷贝", "中", YELLOW,
     "protocol.py:290,295 + ws.py:55,95\n每分片 3-4 次分配+拷贝 = ~1000 次\n可用 memoryview 零拷贝"),
]

for i, (title, severity, color, detail) in enumerate(bottlenecks):
    y = Inches(1.3) + i * Inches(1.5)
    add_rect(sl, Inches(0.8), y, Inches(11.7), Inches(1.35), BG_MID, color)
    add_text(sl, Inches(1.1), y + Inches(0.1), Inches(7), Inches(0.35),
             title, size=16, color=color, bold=True)
    add_text(sl, Inches(9), y + Inches(0.1), Inches(3), Inches(0.35),
             f"严重度: {severity}", size=13, color=color, bold=True, align=PP_ALIGN.RIGHT)
    lines = detail.split("\n")
    add_multiline(sl, Inches(1.1), y + Inches(0.5), Inches(11), Inches(0.8),
                  [(l, GRAY) for l in lines], size=12)


# ════════════════════════════════════════════════════════════════════
# SLIDE 13 — Limitations & Future Work
# ════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
set_bg(sl, BG_DARK)
add_rect(sl, Inches(0), Inches(0), W, Inches(0.06), ACCENT)

add_text(sl, Inches(0.8), Inches(0.4), Inches(10), Inches(0.6),
         "12  局限性与未来工作", size=28, color=ACCENT, bold=True)

# Limitations
add_rect(sl, Inches(0.8), Inches(1.3), Inches(5.8), Inches(5.5), BG_MID, ACCENT2)
add_text(sl, Inches(1.1), Inches(1.5), Inches(5.4), Inches(0.5),
         "当前局限性", size=20, color=ACCENT2, bold=True)
add_bullet_list(sl, Inches(1.1), Inches(2.2), Inches(5.4), Inches(4.3), [
    ("  R2 保留零字节仍然 100% 命中", RED),
    ("  Python 纯实现, 吞吐保留率仅 ~2-4%", RED),
    ("  WS mask/unmask 逐字节循环性能差", RED),
    ("  每分片独立 AEAD 调用, FFI 开销大", YELLOW),
    ("  大量 bytes() 拷贝, 内存分配频繁", YELLOW),
    ("  仅测试本地回环, 未覆盖广域网场景", YELLOW),
    ("  ML 分类器样本量小, 真实对抗待验证", YELLOW),
], size=15)

# Future work
add_rect(sl, Inches(7), Inches(1.3), Inches(5.8), Inches(5.5), BG_MID, ACCENT3)
add_text(sl, Inches(7.3), Inches(1.5), Inches(5.4), Inches(0.5),
         "优化方向", size=20, color=ACCENT3, bold=True)
add_bullet_list(sl, Inches(7.3), Inches(2.2), Inches(5.4), Inches(4.3), [
    ("  修复 R2 保留零字节特征", GREEN),
    ("  C 扩展/PyO3 重写热路径 (50-100x)", GREEN),
    ("  批量随机字节池 (消除系统调用)", GREEN),
    ("  memoryview 零拷贝优化", GREEN),
    ("  合并小分片减少 AEAD 调用", GREEN),
    ("  广域网真实场景测试", ACCENT),
    ("  对抗更强的 DPI 系统 (GFW 级别)", ACCENT),
    ("  多平台部署 (Docker/路由器)", ACCENT),
], size=15)


# ════════════════════════════════════════════════════════════════════
# SLIDE 14 — Thank You
# ════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
set_bg(sl, BG_DARK)
add_rect(sl, Inches(0), Inches(0), W, Inches(0.06), ACCENT)

add_text(sl, Inches(1), Inches(2.5), Inches(11), Inches(1),
         "Thank You", size=52, color=ACCENT, bold=True, align=PP_ALIGN.CENTER)
add_text(sl, Inches(1), Inches(3.8), Inches(11), Inches(0.6),
         "HideWG — WireGuard 流量隐蔽隧道系统", size=22, color=WHITE, align=PP_ALIGN.CENTER)
add_text(sl, Inches(1), Inches(4.8), Inches(11), Inches(0.5),
         "github.com/HuZhipeng-hu/hidewg", size=16, color=GRAY, align=PP_ALIGN.CENTER)

# ── Save ──
output = "HideWG_项目讲解.pptx"
prs.save(output)
print(f"Saved: {output}")
