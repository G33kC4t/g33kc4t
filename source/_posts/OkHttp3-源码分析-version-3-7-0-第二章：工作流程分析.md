---
title: 'OkHttp3 源码分析(version: 3.7.0) - 第二章：工作流程分析'
date: 2017-07-31 11:26:13
tags: OkHttp
categories: Android
---

本章将通过源码分析OkHttp中一个请求从开始到结束整个工作流程中，OkHttp都做了哪些工作，各个组件分别都做了什么工作。我们将对整个流程做分析，对每个重要的流程详细讲解。

<!--more-->

## 大纲
### 重点介绍
我们将重点介绍以下流程

- 一个请求从发送到接收给用户的的整体流程
- 整体流程中每个部分的的工作流程
- 连接的创建和复用与合并

### 忽略部分

- 缓存的获取和存储
- HTTP/HTTPS协议实现
- webSocket部分

## 请求整体流程

在上一章的介绍中，我们了解到Call接口作为真正发送请求的部分，其实现为RealCall类。通过阅读源码，我们发现，不论同步还是异步请求,真实实现发送请求的函数为:
```java
  Response getResponseWithInterceptorChain() throws IOException {
    // Build a full stack of interceptors.
    List<Interceptor> interceptors = new ArrayList<>();
    interceptors.addAll(client.interceptors());
    interceptors.add(retryAndFollowUpInterceptor);
    interceptors.add(new BridgeInterceptor(client.cookieJar()));
    interceptors.add(new CacheInterceptor(client.internalCache()));
    interceptors.add(new ConnectInterceptor(client));
    if (!forWebSocket) {
      interceptors.addAll(client.networkInterceptors());
    }
    interceptors.add(new CallServerInterceptor(forWebSocket));

    Interceptor.Chain chain = new RealInterceptorChain(
        interceptors, null, null, null, 0, originalRequest);
    return chain.proceed(originalRequest);
  }
```
我们发现，OKHTTP请求的每一步都是通过Interceptor接口配合实现，具体的实现流程如下：

![ ](/images/OkHttp详细请求流程.png)

查看源码我们发现，首先各种逻辑被封装为一个个Interceptor，按照顺序Add到了一个List中，然后通过一个RealInterceptorChain开始第一步调用，此时index=0。我们先来看流程图中右边的小图，RealInterceptorChain的proceed函数调用时，会先生成一个新的RealInterceptorChain，并且将当前index+1传入新的RealInterceptorChain，然后用当前的index获取对应的Interceptor，然后用Interceptor.intercept处理新生成的RealInterceptorChain，此时Interceptor.intercept中根据RealInterceptorChain里的参数处理完对应逻辑后，会再次调用RealInterceptorChain的proceed函数，继续上一步逻辑，直到最后一个CallServerInterceptor。代码如下：
```java
    // Call the next interceptor in the chain.
    RealInterceptorChain next = new RealInterceptorChain(
        interceptors, streamAllocation, httpCodec, connection, index + 1, request);
    Interceptor interceptor = interceptors.get(index);
    Response response = interceptor.intercept(next);
```

我们再看左边的大图，其中说明了每个Interceptor所承担的任务。接下来我们将依次说明。

## Interceptor主要子类功能说明
我们首先对每个子类进行描述，让后对主要的几个子类进行详细分析：

- **RetryAndFollowUpInterceptor**
这个类负责请求的初始化和再处理。它里面有一个while循环，首先它创建一个新的StreamAllocation，走接下来的流程发送，等待结果返回后，根据一定条件进行重新打包和重发(重定向/Auth验证等)。不再详细分析，具体清看源码。
- **BridgeInterceptor**
这个类负责完善整个request的信息。主要有requestBody中的头信息，User-Agent等一些用户没有填但是HTTP协议要求填的信息，GZIP压缩信息和Cookie信息等，全部添加到request中，然后继续调用下一步发送，当发送返回后，这个类会跟据返回的Header继续对响应体进行处理。例如保存Cookie，根据header为body添加gzip解压功能等。不再详细分析，具体清看源码。
- **CacheInterceptor**
Cache部分主要负责结果的缓存，它对应Header中的cache部分，在本章不多做介绍。
- **ConnectInterceptor**
顾名思义，这个类负责与服务的连接，当intercept调用，这个类会根据streamAllocation创建或获取一个新的连接，并且生成HttpCodec，为之后的发送准备好基础功能。在[下面](#ConnectInterceptor)我们会介绍这个类的流程。
- **CallServerInterceptor**
负责请求体的转换/发送和响应体的接收/转换，这个类通过调用HttpCodec对http协议的实现，生成二进制流，发送给服务器，并且获取服务器响应，并将body流封装进okio的Source。

## <span id="ConnectInterceptor">ConnectInterceptor</span>
获取连接的流程如下：
![ ](/images/ConnectInterceptor连接流程.png)

接下来介绍一下流程中的几个细节：

- RealConnection 维护了一个StreamAllocation的引用列表 - allocations，用来记录有多少流连接到了这个连接上，当连接池get函数被调用时，主要通过以下函数来判断
**isEligible：**
这个函数会判断当前连接还能否加入更多的流，在没有代理的情况下会判断是否处于同一个地址，在有代理的情况下会判断是否处于同一个路由。然后判断allocations中被引用的数量是否超过要求的最大值，HTTP1.x协议的最大值为1,也是不允许多路复用。最后如果都满足条件则返回连接可以被使用。
- 释放时机： 当我们调用ResponseBody或Response的close时，StreamAllocation从Connect中会被释放，此时调用streamFinished函数，streamFinished会将StreamAllocation从Connect中移除，并且通知调用连接池的connectionBecameIdle函数，最终触发连接池的cleanup清理工作，在清理工作中才真正关闭一个Socket连接。所以我们一定要记得检查是否调用Response的close函数。否则会造成连接的泄漏。



