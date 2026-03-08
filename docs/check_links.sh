#!/bin/bash

# 文档链接检查工具
# Document Link Checker Tool
# 
# 功能 / Features:
# - 检查所有 Markdown 文件中的相对路径链接
# - Check all relative path links in Markdown files
# - 支持跨平台使用（相对路径）
# - Cross-platform support (relative paths)
# - 生成详细的检查报告
# - Generate detailed check reports
#
# 使用方法 / Usage:
#   ./check_links.sh              # 基本检查 / Basic check
#   ./check_links.sh -v           # 详细输出 / Verbose output
#   ./check_links.sh -o report.txt # 输出到文件 / Output to file
#   ./check_links.sh -h           # 显示帮助 / Show help

# 版本信息 / Version info
VERSION="1.0.0"

# 获取脚本所在目录（相对路径支持）
# Get script directory (relative path support)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCS_DIR="$SCRIPT_DIR"

# 颜色定义 / Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 统计变量 / Statistics variables
ERRORS=0
WARNINGS=0
TOTAL_LINKS=0
TOTAL_FILES=0
CHECKED_FILES=0

# 输出控制 / Output control
VERBOSE=false
OUTPUT_FILE=""

# 错误文件列表 / Error files list
declare -a ERROR_FILES
declare -a ERROR_LINKS
declare -a ERROR_TARGETS

# 显示帮助信息 / Show help
show_help() {
    cat << EOF
文档链接检查工具 v${VERSION}
Document Link Checker Tool v${VERSION}

使用方法 / Usage:
  $0 [选项] [选项参数]

选项 / Options:
  -h, --help          显示此帮助信息 / Show this help message
  -v, --verbose       显示详细输出 / Show verbose output
  -o, --output FILE   输出报告到文件 / Output report to file
  -d, --dir DIR       指定检查目录 / Specify check directory
  -V, --version       显示版本信息 / Show version info

示例 / Examples:
  $0                      # 基本检查 / Basic check
  $0 -v                   # 详细输出 / Verbose output
  $0 -o report.txt        # 输出到文件 / Output to file
  $0 -d /path/to/docs     # 检查指定目录 / Check specific directory

退出码 / Exit codes:
  0 - 所有链接正常 / All links are valid
  1 - 发现错误链接 / Found broken links
  2 - 参数错误 / Invalid arguments

EOF
    exit 0
}

# 解析参数 / Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -d|--dir)
                DOCS_DIR="$2"
                shift 2
                ;;
            -V|--version)
                echo "文档链接检查工具 v${VERSION}"
                echo "Document Link Checker Tool v${VERSION}"
                exit 0
                ;;
            *)
                echo -e "${RED}错误: 未知选项 '$1'${NC}"
                echo -e "${RED}Error: Unknown option '$1'${NC}"
                echo "使用 -h 或 --help 查看帮助 / Use -h or --help for help"
                exit 2
                ;;
        esac
    done
}

# 打印函数 / Print functions
print_header() {
    local msg="$1"
    echo -e "${BLUE}=== $msg ===${NC}"
}

print_success() {
    local msg="$1"
    echo -e "${GREEN}✅ $msg${NC}"
}

print_error() {
    local msg="$1"
    echo -e "${RED}❌ $msg${NC}"
}

print_warning() {
    local msg="$1"
    echo -e "${YELLOW}⚠️  $msg${NC}"
}

print_info() {
    local msg="$1"
    if [ "$VERBOSE" = true ]; then
        echo -e "${BLUE}ℹ️  $msg${NC}"
    fi
}

# 检查单个文件 / Check single file
check_file() {
    local file="$1"
    local file_errors=0
    
    # 提取所有相对路径的 .md 链接
    # Extract all relative .md links
    local links=$(grep -oE '\]\([^)]*\.md[^)]*\)' "$file" 2>/dev/null | sed 's/\](\(.*\))/\1/')
    
    if [ -z "$links" ]; then
        return 0
    fi
    
    local dir=$(dirname "$file")
    
    while IFS= read -r link; do
        # 跳过 http/https 链接
        # Skip http/https links
        if [[ "$link" =~ ^http ]]; then
            continue
        fi
        
        TOTAL_LINKS=$((TOTAL_LINKS + 1))
        
        # 解析相对路径
        # Resolve relative path
        local target=""
        if [[ "$link" =~ ^\.\. ]]; then
            target=$(cd "$dir" 2>/dev/null && realpath -m "$link" 2>/dev/null)
        else
            target="$dir/$link"
        fi
        
        # 检查文件是否存在
        # Check if file exists
        if [[ ! -f "$target" ]]; then
            file_errors=$((file_errors + 1))
            ERRORS=$((ERRORS + 1))
            
            ERROR_FILES+=("$file")
            ERROR_LINKS+=("$link")
            ERROR_TARGETS+=("$target")
            
            print_error "错误 / Error in: $(basename "$file")"
            echo "   链接 / Link: $link"
            echo "   目标 / Target: $target"
            echo ""
        else
            print_info "正常 / Valid: $link -> $(basename "$target")"
        fi
    done <<< "$links"
    
    return $file_errors
}

# 生成报告 / Generate report
generate_report() {
    local report=""
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    report+="文档链接检查报告 / Document Link Check Report\n"
    report+="=========================================\n"
    report+="检查时间 / Check Time: $timestamp\n"
    report+="检查目录 / Check Directory: $DOCS_DIR\n"
    report+="\n"
    report+="统计信息 / Statistics:\n"
    report+="  - 检查文件数 / Files Checked: $CHECKED_FILES\n"
    report+="  - 总链接数 / Total Links: $TOTAL_LINKS\n"
    report+="  - 错误数 / Errors: $ERRORS\n"
    report+="  - 警告数 / Warnings: $WARNINGS\n"
    report+="\n"
    
    if [ $ERRORS -gt 0 ]; then
        report+="错误详情 / Error Details:\n"
        report+="-----------------------------------------\n"
        for i in "${!ERROR_FILES[@]}"; do
            report+="错误 $((i+1)) / Error $((i+1)):\n"
            report+="  文件 / File: ${ERROR_FILES[$i]}\n"
            report+="  链接 / Link: ${ERROR_LINKS[$i]}\n"
            report+="  目标 / Target: ${ERROR_TARGETS[$i]}\n"
            report+="\n"
        done
    else
        report+="✅ 所有链接检查通过！/ All links are valid!\n"
    fi
    
    report+="\n"
    report+="检查完成 / Check Completed\n"
    
    # 输出到文件或控制台
    # Output to file or console
    if [ -n "$OUTPUT_FILE" ]; then
        echo -e "$report" > "$OUTPUT_FILE"
        print_success "报告已保存到 / Report saved to: $OUTPUT_FILE"
    fi
    
    echo -e "$report"
}

# 主函数 / Main function
main() {
    parse_args "$@"
    
    print_header "开始检查文档链接 / Starting Document Link Check"
    echo "文档目录 / Docs Directory: $DOCS_DIR"
    echo ""
    
    # 检查目录是否存在
    # Check if directory exists
    if [ ! -d "$DOCS_DIR" ]; then
        print_error "目录不存在 / Directory not found: $DOCS_DIR"
        exit 2
    fi
    
    # 统计文件数
    # Count files
    TOTAL_FILES=$(find "$DOCS_DIR" -name "*.md" -type f | wc -l)
    print_info "找到 / Found $TOTAL_FILES 个 Markdown 文件 / Markdown files"
    echo ""
    
    # 检查所有文件
    # Check all files
    while IFS= read -r file; do
        CHECKED_FILES=$((CHECKED_FILES + 1))
        print_info "检查 / Checking [$CHECKED_FILES/$TOTAL_FILES]: $(basename "$file")"
        check_file "$file"
    done < <(find "$DOCS_DIR" -name "*.md" -type f)
    
    echo ""
    print_header "检查完成 / Check Completed"
    
    # 生成报告
    # Generate report
    generate_report
    
    # 返回退出码
    # Return exit code
    if [ $ERRORS -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
}

# 运行主函数
# Run main function
main "$@"
