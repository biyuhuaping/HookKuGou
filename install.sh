#!/bin/bash
# ==========================================================
# install.sh - Theos tweak 自动打包上传并安装脚本
# 执行命令：zb@ZBmac HookKuGou % ./install.sh
# ==========================================================

# 更新版本
version=`grep '^Version:' control | awk '{print $2}'`
package_name=`grep '^Package:' control | awk '{print $2}'`

# 版本号自增，以点分割，取最后一位自增
base_version=$(echo "$version" | awk -F. 'OFS="."{$NF+=1; print}')
new_version="$base_version"

# 用 sed 替换 control 文件中的 Version 字段
sed -i '' "s/^Version: .*/Version: $new_version/" control

# 输出新版本号
echo "Version updated: $version -> $new_version"

# make 
# make package messages=yes
echo "开始打包 deb..."
make clean package


# THEOS_DEVICE_PORT=11111
THEOS_DEVICE_IP=192.168.1.87 #127.0.0.1

# .jbroot-5F8565E2CA03BC28
# jailbreak_file_path="/var/mobile/Containers/Shared/AppGroup/.jbroot-33BE6A86BB28F200/var/tmp/_theos_install.deb"
jailbreak_file_path="/var/mobile/install.deb"


ROOTLESS=1
ROOTHIDE=0

# 确定 deb 文件路径
deb_name=""
deb_path=""
if [ "$ROOTLESS" -eq 1 ]; then
    deb_name="${package_name}_${new_version}-1+debug_iphoneos-arm64.deb"
elif [ "$ROOTHIDE" -eq 1 ]; then
    deb_name="${package_name}_${new_version}-1+debug_iphoneos-arm64e.deb"
else
    deb_name="${package_name}_${new_version}-1+debug_iphoneos-arm64.deb"
fi

deb_path="./packages/$deb_name"

# if [ ! -f "$deb_path" ]; then
#     echo "打包失败：$deb_path 不存在！"
#     exit 1
# fi
# echo "打包完成: $deb_path"
deb_path=$(ls -t ./packages/*.deb | head -n1)
deb_name=$(basename "$deb_path")

if [ ! -f "$deb_path" ]; then
    echo "打包失败：未找到 deb 文件"
    exit 1
fi
echo "打包完成: $deb_name"


#上传 deb 到设备
# echo "上传 deb 到设备..."
# scp -P $THEOS_DEVICE_PORT "$deb_path" mobile@$THEOS_DEVICE_IP:$jailbreak_file_path
# echo "上传完成: $jailbreak_file_path"


# # 执行安装
# echo "在设备上安装 deb..."
# ssh -tt -p $THEOS_DEVICE_PORT -l mobile $THEOS_DEVICE_IP "sudo dpkg -i $jailbreak_file_path && rm $jailbreak_file_path"
# echo "安装完成"


# # 重启 SpringBoard
# echo "重启 SpringBoard..."
# ssh -tt -p $THEOS_DEVICE_PORT -l mobile $THEOS_DEVICE_IP 'killall -9 SpringBoard'
# echo "SpringBoard 重启完成"

echo "====================="
echo "install.sh 执行完成"
echo "====================="