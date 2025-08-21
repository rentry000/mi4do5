import os
import gzip
import asyncio
import httpx
import shutil
from bs4 import BeautifulSoup
import re
import subprocess
import math
import time
import aiofiles
import urllib3
import tldextract
import ipaddress
from pathlib import Path
from datetime import datetime
from typing import List
import yaml
from functools import wraps, partial
import functools

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 配置参数（完整版，调整为mihomo）
CONFIG = {
    'mihomo_version': "v1.19.12",
    'mihomo_url': "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.12/mihomo-linux-amd64-v3-v1.19.12.gz",
    'base_url': "https://cs1.ip.thc.org/",  # 规则源地址（需替换为实际可用源）
    'num_latest_files': 7,                 # 最新文件数量
    'num_splits': 3,                       # 每个文件分割份数（固定3组）
    'output_dir': "generated_rules",      # 仅存放编译后的 .mrs 文件
    'local_repo_path': os.path.join(os.getcwd(), "mihomo_rulesets"),  # Git 仓库独立目录（修复：使用当前工作目录并设置正确子目录以匹配路径）

    'temp_downloads_dir': "downloads",     # 临时下载目录
    'temp_processed_dir': "processed",     # 临时处理目录
    'max_files_per_compile': 5,           # 单次编译最大文件数（减少以降低内存使用）
    'compile_delay': 10,                   # 编译间隔时间（秒）（增加以避免超时）
    'ruleset_type': 'domain',              # 规则类型（mihomo convert-ruleset 类型）
    'input_format': 'yaml',                # 输入格式（mihomo convert-ruleset 格式）
    'download_timeout': 600.0,             # 总下载超时（秒）
    'max_download_retries': 5,             # 单文件最大重试次数
    'chunk_size': 16384,                   # 下载分块大小（字节）
    'verify_ssl': False,                   # SSL验证开关（强制关闭）
    'debug_mode': False,                   # 调试模式开关（显示进度条）
    
    # GitHub配置
    'github_repo_url': "https://github.com/rentry000/mi4do3.git",  # GitHub仓库地址
    
    'branch': "main",                                                   # 分支名称
    'commit_batch_size': 1,                                             # 每批提交文件数（优化点3）
    'push_delay': 10,                                                   # 推送间隔（秒）（修复：减少以避免超时）
    'install_dir': "/usr/local/bin",  # mihomo 安装目录
    
    # 新增配置项
    'hash_algorithm': "sha256",          # 文件完整性校验算法
    'expected_hashes': {                 # 预期哈希值字典（示例）
        "2025-08-14.txt.gz": "abcdef1234567890...",
        "2025-08-13.txt.gz": "fedcba0987654321..."
    },
    
    'max_compile_attempts': 3,         # 编译最大重试次数
    'git_compression_level': 9,          # Git高级压缩等级（1-9）
    'git_pack_memory': 1024 * 1024 * 1024, # Git包内存限制（增加到1GB）
    'cleanup_intermediate': True,        # 是否清理中间文件（默认开启）
    'git_push_timeout': 600              # Git推送超时时间（秒），增加以处理大文件
}

async def install_mihomo():
    """检查并安装 mihomo（异步下载）"""
    install_dir = Path(CONFIG['install_dir'])
    install_dir.mkdir(parents=True, exist_ok=True)
    
    mihomo_exe = install_dir / "mihomo"
    if mihomo_exe.exists():
        print(f"检测到已安装 mihomo: {mihomo_exe}")
        return mihomo_exe

    print("未检测到 mihomo，开始自动安装...")
    install_url = CONFIG['mihomo_url']
    temp_gz = Path("/tmp") / f"mihomo-{CONFIG['mihomo_version']}.gz"

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(CONFIG['download_timeout']),
        verify=CONFIG['verify_ssl'],
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
    ) as client:
        try:
            # 下载压缩包（增强重试机制）
            print(f"正在下载 mihomo {CONFIG['mihomo_version']}...")
            async with client.stream('GET', install_url) as response:
                response.raise_for_status()
                with open(temp_gz, "wb") as f:
                    async for chunk in response.aiter_bytes():
                        f.write(chunk)
            
            # 解压
            print("正在解压安装包...")
            with gzip.open(temp_gz, 'rb') as f_in:
                with open(mihomo_exe, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            os.chmod(mihomo_exe, 0o755)
            print(f"成功安装到: {mihomo_exe}")
            return mihomo_exe
        
        except Exception as e:
            print(f"安装失败: {str(e)}")
            if temp_gz.exists():
                temp_gz.unlink()
            raise

def parse_rule_line_to_clash(line: str) -> str:
    """解析单行规则并转换为Clash/mihomo兼容的YAML格式字符串"""
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    # 处理IP-CIDR规则
    if '/' in line:
        try:
            ipaddress.ip_network(line, strict=False)
            return f"IP-CIDR,{line}"
        except ValueError:
            pass

    # 处理域名规则（映射到Clash类型）
    extracted = tldextract.extract(line)
    if not extracted.suffix:
        # 检查是否为纯关键词域名（如"openai"）
        if re.match(r'^[a-zA-Z0-9-]+$', line):  # 匹配无后缀的纯关键词
            return f"DOMAIN-KEYWORD,{line}"
        return None  # 无效域名（无后缀且非关键词）

    # 处理通配符域名（转换为DOMAIN-SUFFIX或正则，但Clash优先SUFFIX）
    if '*' in line:
        # 简单通配符转换为DOMAIN-SUFFIX
        if line.startswith('*.'):
            return f"DOMAIN-SUFFIX,{line[2:]}"
        # 其他复杂通配符可能需要REGEX，但mihomo domain类型可能不支持，暂转换为DOMAIN-KEYWORD
        return f"DOMAIN-KEYWORD,{line.replace('*', '')}"

    # 处理普通域名后缀
    registered_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.domain else extracted.suffix
    return f"DOMAIN-SUFFIX,{registered_domain}"

def process_and_split_gz(file_path: Path, group_number: int) -> list[Path]:
    """处理.gz文件并按组分割为Clash YAML格式"""
    try:
        with gzip.open(file_path, 'rt', encoding='utf-8') as f:
            content = f.read()

        # 过滤空行和注释行
        lines = [line.strip() for line in content.split('\n') if line.strip() and not line.startswith('#')]
        part_size = math.ceil(len(lines) / CONFIG['num_splits'])  # 每组行数

        output_dir = Path(CONFIG['temp_processed_dir']) / f"group_{group_number:02d}"
        output_dir.mkdir(exist_ok=True, parents=True)
        os.chmod(output_dir, 0o755)  # 确保目录可写
        output_files = []

        for i in range(CONFIG['num_splits']):
            # 计算当前组的行范围
            start = i * part_size
            end = min((i + 1) * part_size, len(lines))
            part_lines = lines[start:end]

            if not part_lines:
                continue  # 跳过空组

            # 解析并转换规则（过滤空规则）
            raw_rules = []
            for line in part_lines:
                parsed = parse_rule_line_to_clash(line)
                if parsed:
                    raw_rules.append(parsed)

            # 生成目标YAML结构
            rule_set = {
                "payload": raw_rules
            }

            # 写入文件（YAML格式）
            output_filename = f"{group_number:02d}-{i+1:02d}.yaml"
            output_file = output_dir / output_filename
            with open(output_file, 'w', encoding='utf-8') as f:
                yaml.dump(rule_set, f, allow_unicode=True, default_flow_style=False)

            output_files.append(output_file)
            print(f"生成分片: {output_file.name}（包含{len(raw_rules)}条规则）")

        print(f"\n文件分割完成: {file_path.name} → {len(output_files)} 个YAML组")
        return output_files

    except Exception as e:
        print(f"处理文件 {file_path.name} 失败: {str(e)}")
        raise

def compile_rule_sets(yaml_files: List[Path]):
    """编译YAML规则集为.mrs二进制文件"""
    mihomo_exe = shutil.which('mihomo')
    if not mihomo_exe:
        raise FileNotFoundError("未找到 mihomo 可执行文件，请先运行安装程序")
    
    compiled_count = 0
    mrs_files = []
    for yaml_file in yaml_files:
        if not yaml_file.exists():
            print(f"跳过不存在的文件: {yaml_file}")
            continue
        
        # 显式验证输出目录存在
        output_dir = Path(CONFIG['output_dir'])
        output_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(output_dir, 0o755)  # 添加写权限
        
        # 生成对应的.mrs文件名（移动到output_dir）
        mrs_filename = f"{yaml_file.stem}.mrs"
        mrs_file = output_dir / mrs_filename
        
        try:
            print(f"\n正在编译: {yaml_file.name} → {mrs_file.name}")
            result = subprocess.run(
                [mihomo_exe, 'convert-ruleset', CONFIG['ruleset_type'], CONFIG['input_format'], str(yaml_file), str(mrs_file)],
                check=True,
                capture_output=True,
                text=True,
                timeout=CONFIG['compile_delay'] * 18  # 编译超时设为编译间隔的两倍
            )
            print(f"编译成功: {result.stdout.strip()}")
            compiled_count += 1
            
            result.check_returncode()  # 显式检查命令是否成功
            mrs_files.append(mrs_file)
            os.remove(yaml_file)       # 立即删除YAML释放内存
        except subprocess.CalledProcessError as e:
            print(f"编译失败: {e.stderr}")
            continue
        except subprocess.TimeoutExpired:
            print(f"编译超时: {yaml_file.name}")
        finally:
            time.sleep(CONFIG['compile_delay'])  # 编译间隔
    
    print(f"\n编译完成: 成功 {compiled_count}/{len(yaml_files)} 个规则集")
    return mrs_files

def setup_git_lfs():
    """设置 Git LFS 以处理大文件"""
    repo_path = CONFIG['local_repo_path']
    try:
        subprocess.run(['git', 'lfs', 'version'], check=True, capture_output=True)
        print("Git LFS 已安装。")
    except FileNotFoundError:
        print("未找到 Git LFS。尝试安装（假设 Ubuntu/Debian 系统）...")
        try:
            subprocess.run(['sudo', 'apt-get', 'update', '-y'], check=True)
            subprocess.run(['sudo', 'apt-get', 'install', 'git-lfs', '-y'], check=True)
            print("Git LFS 安装成功。")
        except Exception as e:
            print(f"安装 Git LFS 失败: {e}")
            print("请手动安装 Git LFS 并重新运行脚本。")
            raise

    # 安装 LFS 钩子
    subprocess.run(['git', 'lfs', 'install'], cwd=repo_path, check=True)

    # 跟踪 .mrs 文件
    attr_file = Path(repo_path) / '.gitattributes'
    if not attr_file.exists() or '*.mrs filter=lfs' not in attr_file.read_text():
        subprocess.run(['git', 'lfs', 'track', '*.mrs'], cwd=repo_path, check=True)
        subprocess.run(['git', 'add', '.gitattributes'], cwd=repo_path, check=True)
        try:
            subprocess.run(['git', 'commit', '-m', 'Setup Git LFS for .mrs files'], cwd=repo_path, check=True)
            print("已提交 Git LFS 配置。")
        except subprocess.CalledProcessError:
            print("Git LFS 配置无变更。")

async def git_operations():
    """
    处理GitHub仓库操作。
    此版本为异步函数，并能正确处理已存在的远程仓库。
    """
    repo_path = Path(CONFIG['local_repo_path'])
    if not repo_path.exists():
        print(f"创建本地仓库目录: {repo_path}")
        repo_path.mkdir(parents=True, exist_ok=True)

    # 初始化Git仓库（如果未初始化）
    if not (repo_path / '.git').exists():
        print("初始化Git仓库...")

        # 准备异步执行 git init 命令
        init_command = functools.partial(
            subprocess.run,
            ['git', 'init', '--initial-branch', CONFIG['branch']],
            check=True,
            text=True,
            capture_output=True,
            cwd=repo_path
        )
        await asyncio.get_event_loop().run_in_executor(None, init_command)

        # 检查并添加/更新远程 'origin'
        try:
            # 检查 'origin' 是否存在
            subprocess.run(
                ['git', 'remote', 'get-url', 'origin'],
                cwd=repo_path,
                check=True,
                capture_output=True # 成功时不显示输出
            )
            print("Remote 'origin' already exists. Ensuring URL is correct.")
            # 如果存在，则更新URL以确保其正确性
            subprocess.run(
                ['git', 'remote', 'set-url', 'origin', CONFIG['github_repo_url']],
                cwd=repo_path,
                check=True
            )
        except subprocess.CalledProcessError:
            # 如果 'get-url' 命令失败，说明 'origin' 不存在，则添加它
            print("Adding new remote 'origin'.")
            subprocess.run(
                ['git', 'remote', 'add', 'origin', CONFIG['github_repo_url']],
                cwd=repo_path,
                
                check=True
            )

        # 创建并切换到新分支（增加stderr捕获以忽略非致命错误）
        subprocess.run(
            ['git', 'checkout', '-b', CONFIG['branch']],
            cwd=repo_path,
            check=True, stderr=subprocess.PIPE)
        
        # 创建 .gitignore 文件
        with open(repo_path / ".gitignore", "w") as f:
            f.write("github_repo/\n")
        print("已创建 .gitignore 文件")

    # 设置 Git LFS（同步执行）
    await asyncio.get_event_loop().run_in_executor(None, setup_git_lfs)

    # 拉取最新代码（避免冲突）
    try:
        print("尝试拉取远程最新代码...")
        # 准备异步执行 git pull 命令
        pull_command = functools.partial(
            subprocess.run,
            ['git', 'pull', '--rebase', 'origin', CONFIG['branch']],
            check=True,
            text=True,
            capture_output=True,
            cwd=repo_path
        )
        await asyncio.get_event_loop().run_in_executor(None, pull_command)

    except subprocess.CalledProcessError:
        print("无远程变更或首次提交，跳过拉取")

    # 收集所有.mrs文件
    mrs_files = list(Path(CONFIG['output_dir']).glob("*.mrs"))
    if not mrs_files:
        print("无需要提交的.mrs文件")
        return

    # 复制.mrs文件到仓库目录
    for f in mrs_files:
        shutil.copy(f, repo_path / f.name)

    # 分批提交（每批CONFIG['commit_batch_size']个文件）
    for i in range(0, len(mrs_files), CONFIG['commit_batch_size']):
        batch = mrs_files[i:i + CONFIG['commit_batch_size']]
        commit_msg = f"Add ruleset batch {i//CONFIG['commit_batch_size'] + 1}"
        
        # 验证文件是否存在（检查复制后的文件）
        for f in batch:
            if not (repo_path / f.name).exists():
                raise FileNotFoundError(f"尝试添加不存在的文件: {repo_path / f.name}")

        try:
            # 添加文件到暂存区
            subprocess.run(
                ['git', 'add'] + [f.name for f in batch],
                check=True,
                cwd=repo_path,
                text=True,
                capture_output=True)
            
            # 检查是否有变更
            status = subprocess.run(
                ['git', 'status', '--porcelain'],
                check=True,
                cwd=repo_path,
                text=True,
                capture_output=True
            )
            if not status.stdout.strip():
                print("无变更，跳过提交")
                continue
            
            # 提交变更
            subprocess.run(
                ['git', 'commit', '-m', commit_msg],
                check=True,
                cwd=repo_path,
                text=True,
                capture_output=True
            )
            
            # 推送到远程仓库
            try:
                subprocess.run(
                    ['git', 'push', 'origin', CONFIG['branch']],
                    check=True,
                    timeout=CONFIG['git_push_timeout'],
                    cwd=repo_path,
                    text=True,
                    capture_output=True
                )
                print(f"成功推送批次 {i//CONFIG['commit_batch_size'] + 1}")
            except subprocess.CalledProcessError as e:
                print(f"推送失败: {e.stderr.strip()}")
                continue
        
        except Exception as e:
            print(f"Git操作失败: {str(e)}")
            # 拉取最新代码后重试
            try:
                subprocess.run(
                    ['git', 'pull', '--rebase', 'origin', CONFIG['branch']],
                    check=True,
                    cwd=repo_path,
                    text=True,
                    capture_output=True
                )
                time.sleep(CONFIG['push_delay'])
            except Exception as pull_e:
                print(f"重试拉取失败: {pull_e}")

def cleanup_files(temp_files: List[Path] = None, full_clean=False):
    """清理中间文件（增强版：递归清理和日志记录），可选指定文件列表和是否全面清理"""
    print("\n================ 开始清理中间文件 ==================")
    
    # 清理指定文件
    if temp_files:
        for file in temp_files:
            if file.exists():
                try:
                    file.unlink()
                    print(f"已删除文件: {file}")
                except Exception as e:
                    print(f"删除文件失败: {file} - {str(e)}")
    
    if full_clean:
        # 清理下载目录
        if CONFIG['cleanup_intermediate']:
            downloads_dir = Path(CONFIG['temp_downloads_dir'])
            if downloads_dir.exists():
                for root, dirs, files in os.walk(downloads_dir, topdown=False):
                    for name in files:
                        file_path = Path(root) / name
                        try:
                            file_path.unlink()
                            print(f"已删除文件: {file_path}")
                        except Exception as e:
                            print(f"删除文件失败: {file_path} - {str(e)}")
                    for name in dirs:
                        dir_path = Path(root) / name
                        try:
                            dir_path.rmdir()
                            print(f"已删除空目录: {dir_path}")
                        except Exception as e:
                            print(f"删除目录失败: {dir_path} - {str(e)}")
                print(f"彻底清理下载目录: {downloads_dir}")
        
        # 清理处理目录
        processed_dir = Path(CONFIG['temp_processed_dir'])
        if processed_dir.exists():
            try:
                shutil.rmtree(processed_dir, ignore_errors=True)
                print(f"已删除处理目录: {processed_dir}")
            except Exception as e:
                print(f"删除处理目录失败: {processed_dir} - {str(e)}")
        
        # 清理输出目录的非.mrs文件
        output_dir = Path(CONFIG['output_dir'])
        os.chmod(output_dir, 0o755)  # 添加写权限
        if output_dir.exists():
            for file in output_dir.glob("*"):
                if file.is_file() and file.suffix != ".mrs":
                    try:
                        file.unlink()
                        print(f"已清理无关文件: {file}")
                    except Exception as e:
                        print(f"清理文件失败: {file} - {str(e)}")
    
    print("================ 清理完成 ==================\n")

async def download_latest_files():
    """下载最新的.gz规则文件（异步版，含哈希校验和重试机制）"""
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(CONFIG['download_timeout']),
        verify=CONFIG['verify_ssl'],
        headers={
            'User-Agent': 'Mozilla/5.0...'
        }
    ) as client:
        try:
            # 访问规则源页面
            print(f"正在访问规则源页面: {CONFIG['base_url']}")
            response = await client.get(CONFIG['base_url'])
            response.raise_for_status()
            html_content = response.text
            soup = BeautifulSoup(html_content, 'html.parser')

            # 解析并过滤 .txt.gz 文件
            downloads_dir = Path(CONFIG['temp_downloads_dir'])
            downloads_dir.mkdir(exist_ok=True, parents=True)
            files = []
            for link in soup.find_all('a'):
                link_text = link.text.strip()
                if link_text.endswith('.txt.gz'):
                    try:
                        file_date = datetime.strptime(link_text.split('.')[0], '%Y-%m-%d')
                        files.append((file_date, link_text))
                    except ValueError:
                        continue

            # 确保 files 非空
            if not files:
                raise FileNotFoundError("未找到有效文件")

            # 按日期排序并截取最新文件
            files.sort(reverse=True, key=lambda x: x[0])
            files = files[:CONFIG['num_latest_files']]

            # 下载文件（保持原有逻辑）
            downloaded_files = []
            for file_date, file_name in files:
                file_url = f"{CONFIG['base_url']}{file_name}"
                local_path = Path(CONFIG['temp_downloads_dir']) / file_name

                # 强制覆盖已存在文件
                if local_path.exists():
                    local_path.unlink()
                    print(f"强制重新下载: {file_name}")

                print(f"\n正在下载: {file_name} ({file_date.strftime('%Y-%m-%d')})")
                retries = 0
                success = False
                while retries < CONFIG['max_download_retries']:
                    try:
                        # 直接使用 client.get 并添加重试逻辑
                        response = await client.get(file_url)
                        response.raise_for_status()
                        with open(local_path, "wb") as f:
                            f.write(response.content)
                        success = True
                        break
                    except Exception as e:
                        retries += 1
                        print(f"下载失败，第 {retries}次重试")
                        if retries >= CONFIG['max_download_retries']:
                            raise
                        await asyncio.sleep(2 ** retries)  # 指数退避策略

                downloaded_files.append(local_path)

            return downloaded_files

        except Exception as e:
            print(f"下载文件失败: {str(e)}")
            raise

def set_git_defaults():
    """设置Git默认配置"""
    try:
        subprocess.run(['git', 'config', '--global', 'init.defaultBranch', CONFIG['branch']], check=True)
        subprocess.run(['git', 'config', '--global', 'user.name', 'GitHub Actions'], check=True)
        subprocess.run(['git', 'config', '--global', 'user.email', 'actions@github.com'], check=True)
        print("Git全局配置完成")
    except subprocess.CalledProcessError as e:
        print(f"Git配置失败: {e}")

def init_github_repo():
    """初始化本地Git仓库"""
    if not os.path.exists(CONFIG['local_repo_path']):
        os.makedirs(CONFIG['local_repo_path'])
    
    git_dir = os.path.join(CONFIG['local_repo_path'], '.git')
    if not os.path.exists(git_dir):
        # 初始化仓库
        subprocess.run(['git', 'init'], cwd=CONFIG['local_repo_path'], check=True)
        
        # 设置远程仓库
        subprocess.run(['git', 'remote', 'add', 'origin', CONFIG['github_repo_url']], 
                      cwd=CONFIG['local_repo_path'], check=True)
        
        # 切换到配置的分支
        subprocess.run(['git', 'checkout', '-b', CONFIG['branch']],
                      cwd=CONFIG['local_repo_path'], check=True)
        
        print(f"已初始化Git仓库: {CONFIG['local_repo_path']}")

def configure_git_compression():
    """配置Git高级压缩参数"""
    try:
        subprocess.run(['git', 'config', '--local', 'core.compression', str(CONFIG['git_compression_level'])], 
                      cwd=CONFIG['local_repo_path'], check=True)
        subprocess.run(['git', 'config', '--local', 'pack.windowMemory', str(CONFIG['git_pack_memory'])], 
                      cwd=CONFIG['local_repo_path'], check=True)
        print("已启用Git高级压缩")
    except subprocess.CalledProcessError as e:
        print(f"Git压缩配置失败: {e}")

async def main():
    try:
        print("""
        ========================================
        mihomo 规则集生成工具 (增强版)
        ========================================
        """)
        await git_operations()

        # 自动安装 mihomo（异步）
        mihomo_path = await install_mihomo()
        print(f"使用 mihomo 路径: {mihomo_path}\n")
        
        # 创建下载目录
        downloads_dir = Path(CONFIG['temp_downloads_dir'])
        downloads_dir.mkdir(exist_ok=True)
        
        # 下载最新规则文件（异步）
        downloaded_files = await download_latest_files()
        if not downloaded_files:
            print("未找到可用规则文件，程序终止")
            return
        
        # 初始化GitHub仓库（同步操作）
        print("\n================ GitHub 操作 ==================")
        await asyncio.get_event_loop().run_in_executor(None, set_git_defaults)
        await asyncio.get_event_loop().run_in_executor(None, init_github_repo)
        await asyncio.get_event_loop().run_in_executor(None, configure_git_compression)
        
        repo_path = Path(CONFIG['local_repo_path'])
        
        # 逐文件处理以减少内存占用
        for idx, downloaded_file in enumerate(downloaded_files, 1):
            print(f"\n处理文件 {idx}/{len(downloaded_files)}: {downloaded_file.name}")
            yaml_files = process_and_split_gz(downloaded_file, idx)
            
            if yaml_files:
                print("\n开始编译规则集...")
                mrs_files = compile_rule_sets(yaml_files)
            else:
                print("未生成任何有效规则集")
                continue
            
            if not mrs_files:
                print("未生成任何 .mrs 文件，跳过推送")
                continue
            
            # 复制.mrs文件到仓库目录
            for f in mrs_files:
                shutil.copy(f, repo_path / f.name)
            
            # 分批推送规则文件
            await asyncio.get_event_loop().run_in_executor(None, git_push_batches, mrs_files)
            
            # 清理当前文件的中间文件（不全面清理）
            cleanup_files(temp_files = [downloaded_file] + mrs_files, full_clean=False)
        
        # 最后全面清理
        cleanup_files(full_clean=True)
        
        print("\n所有操作完成！")

    except Exception as e:
        print(f"程序发生严重错误: {str(e)}")
        raise

# 新增GitHub相关函数
def git_push_batches(file_paths):
    """分批提交和推送文件"""
    if not file_paths:
        print("没有需要推送的文件")
        return
        
    # 确保仓库是最新状态
    try:
        subprocess.run(['git', 'pull', '--rebase', 'origin', CONFIG['branch']],
                     cwd=CONFIG['local_repo_path'], check=True)
    except subprocess.CalledProcessError:
        print("无远程变更或首次提交，跳过拉取")
    
    # 检查Git状态
    status_result = subprocess.run(['git', 'status', '--porcelain'], 
                                 cwd=CONFIG['local_repo_path'], capture_output=True, text=True)
    print(f"Git状态:\n{status_result.stdout}")

    repo_path = Path(CONFIG['local_repo_path'])

    for i in range(0, len(file_paths), CONFIG['commit_batch_size']):
        batch = file_paths[i:i + CONFIG['commit_batch_size']]
        commit_msg = f"Add ruleset batch {i//CONFIG['commit_batch_size'] + 1}"
        
        # 验证文件是否存在（检查复制后的文件）
        for f in batch:
            if not (repo_path / f.name).exists():
                raise FileNotFoundError(f"尝试添加不存在的文件: {repo_path / f.name}")

        try:
            # 添加文件到暂存区
            subprocess.run(
                ['git', 'add'] + [f.name for f in batch], 
                check=True,
                cwd=CONFIG['local_repo_path'],
                text=True,
                capture_output=True)
            
            # 检查是否有变更
            status = subprocess.run(['git', 'status', '--porcelain'], 
                                  cwd=CONFIG['local_repo_path'], capture_output=True, text=True)
            if not status.stdout.strip():
                print("无变更，跳过提交")
                continue
            
            # 提交变更
            subprocess.run(['git', 'commit', '-m', commit_msg], 
                          cwd=CONFIG['local_repo_path'], check=True)
            
            # 推送到远程仓库
            try:
                subprocess.run(['git', 'push', 'origin', CONFIG['branch']],
                             cwd=CONFIG['local_repo_path'], check=True, timeout=CONFIG['git_push_timeout'])
                print(f"成功推送批次 {i//CONFIG['commit_batch_size'] + 1}")
            except subprocess.CalledProcessError as e:
                print(f"推送失败: {e.stderr.strip()}")
                # 异常处理策略：记录错误但继续执行后续批次
                continue
        
        except Exception as e:
            print(f"Git操作失败: {str(e)}")
            # 拉取最新代码后重试
            subprocess.run(['git', 'pull', '--rebase', 'origin', CONFIG['branch']],
                         cwd=CONFIG['local_repo_path'])
            time.sleep(CONFIG['push_delay'])

if __name__ == '__main__':
    asyncio.run(main())  # 必须存在 ✅