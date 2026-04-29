#!/bin/bash
#
# write-message.sh
#
# 将一串文本写入 message.txt 文件，作为后续 SHA-256 + RSASSA-PSS 签名的待签名数据。
#
# 用法：
#   ./write-message.sh               # 使用默认文本
#   ./write-message.sh "你的文本"     # 使用自定义文本
#
# 输出：
#   message.txt                      # 待签名文件

set -euo pipefail

OUTPUT_FILE="message.txt"
DEFAULT_MESSAGE="Hello CloudHSM RSASSA-PSS! This is a test message for SHA-256 + PSS (salt=32) signing."

if [ $# -ge 1 ]; then
    MESSAGE="$1"
else
    MESSAGE="$DEFAULT_MESSAGE"
fi

# 使用 printf（而不是 echo）以避免尾部换行带来的歧义
printf '%s' "$MESSAGE" > "$OUTPUT_FILE"

echo "已写入文件: $OUTPUT_FILE"
echo "文件内容:   $(cat "$OUTPUT_FILE")"
echo "文件大小:   $(wc -c < "$OUTPUT_FILE") bytes"

# 同时显示一下 SHA-256 预期值（方便与 Java 签名程序打印的 hash 做对比）
if command -v sha256sum &>/dev/null; then
    echo "SHA-256 预期值（参考）: $(sha256sum "$OUTPUT_FILE" | awk '{print $1}')"
elif command -v shasum &>/dev/null; then
    echo "SHA-256 预期值（参考）: $(shasum -a 256 "$OUTPUT_FILE" | awk '{print $1}')"
fi
