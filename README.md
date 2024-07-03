# 加解密核心工具（tool.encryptionAndDecryption.core） 

 **version 0.1.0**

<!-- toc -->

### 简介

本工具类是基于bouncycastle的在封装,主要实现了如下功能
* 支持国密、RSA证书本地 生成、签发、签名\验签、加密\解密
* 支持国密单\双证 CA签发模式
* 支持RSA  CA签发模式
* 支持MD5\SHA\SM3等摘要算法
* 支持AES\DES\SM4等对称加密算法

git：  https://github.com/819548945/tool.encryptionAndDecryption.core

文档： http://doc.lich.me/0.1.x/encryptionAndDecryption.core.html

bug、意见反馈: liuchao_@outlook.com

### 安装

maven

````xml
<dependency>
  <groupId>com.github.819548945</groupId>
  <artifactId>tool.encryptionAndDecryption.core</artifactId>
  <version>0.1.0</version>
</dependency>
````
