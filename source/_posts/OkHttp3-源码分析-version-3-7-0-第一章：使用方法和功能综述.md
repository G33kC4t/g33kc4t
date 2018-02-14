---
title: 'OkHttp3 源码分析(version: 3.7.0) - 第一章：使用方法和功能综述'
date: 2017-07-31 11:17:46
tags: OkHttp
categories: Android
---

**OKHTTP提供了一套易使用，功能明确，耦合性低的请求接口，我们首先通过以下几段代码来了解使用方法和其中的设计思路，然后通过对OKHTTP对外提供的所有功能类讲解来了解OKHTTP的使用**

<!--more-->

## 基本请求
### GET 请求实例
```java
private void demoOkHttpGet() {

    Request request = new Request
            .Builder()
            .addHeader("X-AC", "XXX")
            .url("http://www.baidu.com/")
            .get()
            .build();

    OkHttpClient okc = new OkHttpClient
            .Builder()
            .connectionPool(new ConnectionPool(5, 5, TimeUnit.MINUTES))
            .addNetworkInterceptor(new Interceptor() {
                @Override
                public Response intercept(Chain chain) throws IOException {
                    return chain.proceed(chain.request());
                }
            })
            .build();

    Call call = okc
            .newCall(request);

    try {
        Response response = call.execute();
        int code = response.code();
        ResponseBody body = response.body();
        Source source = body.source();
        // source output
        source.close();
    } catch (IOException ignored) {
    }
}
```
#### 综述
一个基本的OkHttp请求分为Request - 请求体封装，OkHttpClient - 发送器参数封装，Call - 发送器接口和Response - 响应体封装。我们依次说明每个部分的功能。

#### Request部分
 Request类封装了HTTP协议中的请求体信息。其中有URL，请求类型（GET，POST），域名（HOSTNAME）等，还有其他标准或自定义的HEADER协议和Body。Request提供了方法去设置请求的Header信息，如果需要设置请求的请求体（REQUEST BODY）或设置上传文件需要通过RequestBody。

#### OkHttpClient部分
OkHttpClient类封装了完成一个完整请求所需的所有参数，其中包括：

1. OkHttp任务调度相关参数 - 线程队列，连接池等
2. HTTP协议中一些可选功能的实现 - KEPPALIVE缓存，SSL验证等
3. 网络层相关参数 - ScocketFactory，DNS解析代理，Proxy网络代理等
以上各个参数功能会在下一部分中介绍

#### Call部分
Call接口封装了一整套HTTP请求的发送，接收和调度逻辑，是整个OkHttp组件的功能核心。其中包括对请求的：

1. 前置处理（前置拦截器）
2. 与服务器的连接
2. 发送 / 接收
2. HTTP协议解析 - 生成 Response
2. 对响应的在处理（后置拦截器）
2. 一些HTTP协议相关动作的执行（GZIP解压，KEEPLIVE缓存，301/302重定向等）

#### Response部分
Response类封装了HTTP协议中响应体的信息。参数有请求返回码，返回的Header（例如ContentLength）等，同时使用.body()函数返回请求的body,请求的bdoy体信息通过ResponseBody来封装

#### ResponseBody部分
ResponseBody类主要封装了响应结果的数据体（body），提供了对body的一系列读取方法。

### POST 请求实例
```java
private void demoOkHttpPost() {

    RequestBody requestBody = new MultipartBody
            .Builder()
            .addFormDataPart("hashCode", "xxx")
            .build();

    Request request = new Request
            .Builder()
            .url("https://www.up.file.com")
            .post(requestBody)
            .build();

    OkHttpClient okc = new OkHttpClient
            .Builder()
            .connectionPool(new ConnectionPool(5, 5, TimeUnit.MINUTES))
            .addNetworkInterceptor(new Interceptor() {
                @Override
                public Response intercept(Chain chain) throws IOException {
                    return chain.proceed(chain.request());
                }
            })
            .hostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            })
            .build();

    Call call = okc
            .newCall(request);

    call.enqueue(new Callback() {
        @Override
        public void onFailure(Call call, IOException e) {

        }

        @Override
        public void onResponse(Call call, Response response) throws IOException {
            int code = response.code();
            ResponseBody body = response.body();
            Source source = body.source();
            // source output
            source.close();
        }
    });
}
```

#### RequestBody部分
若需要[向服务器提交数据](#request_response4)（文件/表单/JSON），需要填写在在Request的Body部分，这一部分规则OKHTTP提供了RequestBody类来实现。OKHTTP根据HTTP标准协议实现了FormBody和MultipartBody.
FormBody协议主要实现了"application/x-www-form-urlencoded" （原生表单提交），在Body中数据以键值对形式存在，每个键值对以&分割（其实就是一版请求时?后面的参数）
MultipartBody（[rfc2387](http://www.ietf.org/rfc/rfc2387.txt)）实现了通过自定义的方式提交数据，可以通过修改其参数使用不同的方式提交数据。
我们还可以通过继承RequestBody来实现自定义类型的数据提交，或者二次修改Body。

例如VV音乐中的上传文件代码
```java
public static class RequestBodyUpload extends RequestBody {

    private static final int BYTE_SIZE = 512 * 1024;

    private final Logger _log = Logger.createLogger(getClass());
    private final AbstractTransferInfomation infomation;
    private final ByteBuffer byteBuffer;
    private final byte[] content = new byte[BYTE_SIZE];
    private final Subscriber subscriber;

    public RequestBodyUpload(AbstractTransferInfomation infomation, ByteBuffer byteBuffer, Subscriber subscriber) {
        this.infomation = infomation;
        this.byteBuffer = byteBuffer;
        this.subscriber = subscriber;
    }

    @Override
    public MediaType contentType() {
        return MediaType.parse("multipart/form-data");
    }

    @Override
    public long contentLength() throws IOException {
        return infomation.getFileSize();
    }

    @Override
    public void writeTo(final BufferedSink sink) throws IOException {
        infomation.setCreateTime(System.currentTimeMillis());
        sink.writeAll(
                new Source() {
                    @Override
                    public long read(Buffer sink, long byteCount) throws IOException {
                        if (byteCount < 0)
                            throw new IllegalArgumentException("byteCount < 0: " + byteCount);
                        if (byteCount == 0)
                            return 0;
                        if (byteBuffer == null) {
                            return -1;
                        }
                        long size = -1;
                        long position = infomation.getPosition();
                        long fileSize = infomation.getFileSize();
                        _log.i("Read start byteCount=%d, position=%d, fileSize=%d", byteCount, position, fileSize);
                        if (position < fileSize) {
                            size = Math.min(fileSize - position, BYTE_SIZE);
                            byteBuffer.get(content, 0, (int) size);
                            sink.write(content, 0, (int) size);
                            position += size;
                            byteCount += size;
                            infomation.setPosition(position);
                        }
                        subscriber.onNext(infomation);
                        _log.i("Read end byteCount %d", byteCount);
                        return size;
                    }

                    @Override
                    public Timeout timeout() {
                        return new Timeout();
                    }

                    @Override
                    public void close() throws IOException {
                    }
                });
    }
}
```

---

## OKHTTP 3.7.0 类功能综述
我将对OKHTTP-3.7.0框间中的所有对外提供的类做一些说明，我将它们分为四部分来描述：

- 对HTTP协议的封装
协议层主要实现了HTTP协议参数和功能的封装，讲解这部分类的同时会简单引入部分[HTTP协议 [1]](#http_rfc)的说明，首先我们先对协议层部分对外开放类进行说明，更多内部实现我们在内部讲解中介绍。
- 资源调度工具
资源调度工具主要实现了对线程/网络连接/缓存等系统资源的管理，这一部分中线程管理和网络连接复用部分将重点说明
- 网络层
网络层部分通过JavaSocket实现了HTTP底层数据包的发送和接收，同时支持自定义的Socket相关参数，地址和代理等。这部分我们仅在讲述逻辑时介绍功能，不单独做分析。
- 业务流程封装（Call，interceptor）
业务流程相关类是OKHTTP的功能核心，是OKHTTP独有的调度逻辑，也是为什么OKHTTP比别的框间快的主要原因，这里我会详细介绍每个类的职责和他们的使用方法

以下是层级关系图
![ ](/images/OKHTTP层级关系图.png)

### 协议层类分析
#### Request

```java
/**
 * An HTTP request. Instances of this class are immutable if their {@link #body} is null or itself
 * immutable.
 */
public final class Request {
  final HttpUrl url;
  final String method;
  final Headers headers;
  final RequestBody body;
  final Object tag;

  private volatile CacheControl cacheControl; // Lazily initialized.
```

HTTP请求的抽象，其中包含了：

- url URL的解析类，代表了请求体中的URL部分 - [HttpUrl](#HttpUrl)
- method 请求类型的解析（GET,POST等）
- headers HEADER部分的封装 - [Headers [2]](#header)
- body 请求Body部分的封装和body相关header（长度等） - [RequestBody [3.4]](#request_response4)
- tag 请求的TAG，支持设置请求的TAG，请求发出后，可以通过拦截器获取Chain，从而获取Request，这时可以通过TAG标识分辨Rquest，或者传递信息

#### <span id="HttpUrl">HttpUrl</span>
请求体中[URL部分 [3]](#request_response)的抽象，包括了以下部分：

- scheme（即http/https）
- username/password （有些HTTP协议支持的用户名密码）
- host 即域名，也可能直接是IP地址
- port 端口

#### Response
```java
/**
 * An HTTP response. Instances of this class are not immutable: the response body is a one-shot
 * value that may be consumed only once and then closed. All other properties are immutable.
 *
 * <p>This class implements {@link Closeable}. Closing it simply closes its response body. See
 * {@link ResponseBody} for an explanation and examples.
 */
public final class Response implements Closeable {
  final Request request;
  final Protocol protocol;
  final int code;
  final String message;
  final Handshake handshake;
  final Headers headers;
  final ResponseBody body;
  final Response networkResponse;
  final Response cacheResponse;
  final Response priorResponse;
  final long sentRequestAtMillis;
  final long receivedResponseAtMillis;

  private volatile CacheControl cacheControl; // Lazily initialized.
```
HTTP响应体的抽象，其中包含了：

- protocol Protocol [HTTP版本 [3]](#request_response3)
- code [HTTP返回码 [3.1]](#request_response1)
    例如一个成功的响应体会返回200 OK 200为code OK 为message
- message 服务器返回的code码对应的信息
- handshake 保存了TCP连接时三次握手协议的信息
- headers 保存了响应头的信息
- body 保存了响应体信息，其中也包括Header中的跟Body有关的信息，例如ContentLength。
- networkResponse/cacheResponse/priorResponse 
- sentRequestAtMillis 保存发送请求的真实时间，这个时间表示客户端第一次发送数据的时间。这个时间不包括客户端Connect的时间。
- receivedResponseAtMillis 开始接受请求的时间，此时Response的Header已经返回，body还没有接收。
- cacheControl 缓存相关，暂时忽略。

#### OkHttpClient
```java

/**
 * Factory for {@linkplain Call calls}, which can be used to send HTTP requests and read their
 * responses.
 */
public class OkHttpClient implements Cloneable, Call.Factory, WebSocket.Factory {

  final Dispatcher dispatcher;
  final Proxy proxy;
  final List<Protocol> protocols;
  final List<ConnectionSpec> connectionSpecs;
  final List<Interceptor> interceptors;
  final List<Interceptor> networkInterceptors;
  final ProxySelector proxySelector;
  final CookieJar cookieJar;
  final Cache cache;
  final InternalCache internalCache;
  final SocketFactory socketFactory;
  final SSLSocketFactory sslSocketFactory;
  final CertificateChainCleaner certificateChainCleaner;
  final HostnameVerifier hostnameVerifier;
  final CertificatePinner certificatePinner;
  final Authenticator proxyAuthenticator;
  final Authenticator authenticator;
  final ConnectionPool connectionPool;
  final Dns dns;
  final boolean followSslRedirects;
  final boolean followRedirects;
  final boolean retryOnConnectionFailure;
  final int connectTimeout;
  final int readTimeout;
  final int writeTimeout;
  final int pingInterval;

```
OkHttpClient是请求的核心接口，对于OkHttpClient上的文档说明比较多，我只Copy了最主要的一段话，OkHttpClient是Call的Factory，它主要用来创建一个请求的抽象，管理了一个请求所需的所有参数，它通过Build模式来创建，可以配置的参数如下：

- dispatcher 主要负责请求的调度，处理了请求过程中线程的管理和分配，Dispatcher记录了所有等待或执行中的Call（不论阻塞或者非阻塞调用后都保存在这个类中），具体逻辑在下面单独介绍
- proxy 封装了网络层代理，是JavaSocket的API，具体使用请看JavaSocket编程的代理部分
- protocols 设置支持哪些[HTTP协议（1.0/1.1/2.0等）[3.3]](#request_response3)
- connectionSpecs 设置支持哪些[HTTPS安全配置 [1.4]](#http_rfc4)
- interceptors 无网络状态时的拦截器，注册在这里的拦截器会在网络链接前和响应体返回后回调
- networkInterceptors 有网络状态时的拦截器，注册在这里的拦截器会在网络链接后发送数据前回调，并且chain在接受数据完成，断开前返回
- proxySelector JavaSocket相关接口，主要处理代理的选择，不多做叙述
- cookieJar 负责管理cookie相关功能
- cache 缓存相关逻辑
- internalCache 缓存适配器，可以通过这个接口自定义缓存的存取
- socketFactory JavaSocket工厂，可以通过这个工厂自定义底层的socket连接
- sslSocketFactory HTTPS用的
- hostnameVerifier 这个用于验证HTTPS证书是否有效
- certificatePinner HTTPS加密相关类
- proxyAuthenticator/authenticator 服务器配置需要使用用户名密码时，这个类用来处理[认证流程 [1.5]](#http_rfc5)
- connectionPool OKHTTP连接池，负责管理Socket连接，实现了连接的存储和复用
- dns 提供了可以自定义处理DNS的接口，如果没有设置默认用JAVA的
- followRedirects 是否允许任何形式的重定向
- followSslRedirects 是否允许在HTTPS和HTTP之间重定向
- retryOnConnectionFailure 当连接发生错误时是否允许重试
- connectTimeout/readTimeout/writeTimeout 超时时间
- pingInterval websocket心跳包间隔

以上为协议层对对外开放的全部可配置参数，OkHttp对HTTP协议的内部实现分别在 

- okhttp3.internal.http
主要包含了HTTP协议各个部分参数的基础类，和HTTP各个版本中基础的部分
- okhttp3.internal.http1
HTTP 1.0/1.1请求的打包和解包，主要类Http1Codec
- okhttp3.internal.http2
HTTP 2.0 请求的打包和解包和对HTTP2一些特性的实现，主要类Http2Codec
- okhttp3.internal.ws
包含了websocket的[实现](#websocket1)

### HTTP协议相关文章
#### <span id="http_rfc">1. HTTP协议相关文章</span>

- <span id="http_rfc1">[1.1]</span> [简介帮助理解](http://www.tuicool.com/articles/jMFfIv)
- <span id="http_rfc2">[1.2]</span> [HTTP协议全解析](http://www.cnblogs.com/li0803/archive/2008/11/03/1324746.html)
- <span id="http_rfc3">[1.3]</span> [官方协议全解析](https://www.w3.org/Protocols/rfc2616/rfc2616.html)
- <span id="http_rfc4">[1.4]</span>[OKHTTP中HTTPS协议控制](http://www.tuicool.com/articles/3YNrmin)
- <span id="http_rfc5">[1.5]</span>[Authorization认证过程](http://blog.csdn.net/wwwsq/article/details/7255062)
- <span id="http_rfc6">[1.6]</span>[HTTP2多路复用](http://www.blogjava.net/yongboy/archive/2015/03/19/423611.aspx)

#### <span id="header">2. HEADER相关文章</span>

- <span id="header1">[2.1]</span> [HEADER头说明列表](http://kb.cnblogs.com/page/92320/)
- <span id="header2">[2.2]</span> [官方rfc](https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html)

#### <span id="request_response">3. REQUEST 和 RESPONSE</span>

- <span id="request_response1">[3.1]</span> [HTTP响应码百度百科](http://baike.baidu.com/link?url=ye0PXBjc_t0B4e-DvKSsx3oBdSB_SNszXcOXQKQTaqwD0NEv0e9rmBxGWyvbvyHyumkRJiwDe9mP8UGrqwBqWJK43Y3fmbWKaBhyrnXPAXIVP0hgZulzUp6KCa6Pyllb)
- <span id="request_response2">[3.2]</span> [HTTP请求类型](http://www.cnblogs.com/yin-jingyu/archive/2011/08/01/2123548.html)
- <span id="request_response3">[3.3]</span> [HTTP 1.0/1.1/2.0 主要区别](http://blog.csdn.net/linsongbin1/article/details/54980801)
- <span id="request_response4">[3.4]</span> [Http POST 提交数据的四种方式解析](http://www.jianshu.com/p/e47abb91465d)

#### <span id="websocket">4. WEBSOCKET相关

- <span id="websocket1">[4.1]</span> [百度百科websocket](http://baike.baidu.com/link?url=x28Z2QZUU7xc7SnW5v_0ij4pBUZBk3jQXCBOPLZy-zeEFp4hnphBeQuFl6MWt4Ehp7UvAAAcm-jB9zzF-kEhRjPZpuMV3CtrLQgcUUsVn2W)

### 调度层工具
调度层工具我们仅介绍线程管理和连接池两个类，

#### Dispatcher
```java
/**
 * Policy on when async requests are executed.
 *
 * <p>Each dispatcher uses an {@link ExecutorService} to run calls internally. If you supply your
 * own executor, it should be able to run {@linkplain #getMaxRequests the configured maximum} number
 * of calls concurrently.
 */
public final class Dispatcher {
  private int maxRequests = 64;
  private int maxRequestsPerHost = 5;
  private Runnable idleCallback;

  /** Executes calls. Created lazily. */
  private ExecutorService executorService;

  /** Ready async calls in the order they'll be run. */
  private final Deque<AsyncCall> readyAsyncCalls = new ArrayDeque<>();

  /** Running asynchronous calls. Includes canceled calls that haven't finished yet. */
  private final Deque<AsyncCall> runningAsyncCalls = new ArrayDeque<>();

  /** Running synchronous calls. Includes canceled calls that haven't finished yet. */
  private final Deque<RealCall> runningSyncCalls = new ArrayDeque<>();
```
Dispatcher类负责线程资源的分配和回收，它根据域名和可自定义的线程池控制线程的分配。

- maxRequests 最大可分配线程数
- maxRequestsPerHost 单个域名最大可分配线程数
- idleCallback 一个可设置的任务，当没有任何一个任务在执行时，调用此回调
- executorService自定义线程池
- readyAsyncCalls 等待中的异步任务队列
- runningAsyncCalls 正在运行中的异步任务队列
- runningSyncCalls 正在运行中的同步任务队列

以下是分配和回收的流程图
![ ](/images/Dispatcher流程图.png)

当用户发起一个异步请求时，OkHttp通过调用synchronized void enqueue(AsyncCall call)函数请求线程，enqueue判断当前使用线程数是否小于maxRequests，并且通过int runningCallsForHost(AsyncCall call) 函数判断当前请求的域名是否超出域名限制。之后加入请求队列或者加入等待队列。

当一个请求（同步或异步）完成时，OkHttp逻辑层调用finished释放资源，finished函数会remove对应队列的任务，然后整理队列，将等待中的下一个队列入队。

#### ConnectionPool
```java
/**
 * Manages reuse of HTTP and HTTP/2 connections for reduced network latency. HTTP requests that
 * share the same {@link Address} may share a {@link Connection}. This class implements the policy
 * of which connections to keep open for future use.
 */
public final class ConnectionPool {
  /**
   * Background threads are used to cleanup expired connections. There will be at most a single
   * thread running per connection pool. The thread pool executor permits the pool itself to be
   * garbage collected.
   */
  private static final Executor executor = new ThreadPoolExecutor(0 /* corePoolSize */,
      Integer.MAX_VALUE /* maximumPoolSize */, 60L /* keepAliveTime */, TimeUnit.SECONDS,
      new SynchronousQueue<Runnable>(), Util.threadFactory("OkHttp ConnectionPool", true));

  /** The maximum number of idle connections for each address. */
  private final int maxIdleConnections;
  private final long keepAliveDurationNs;
  private final Runnable cleanupRunnable = new Runnable() {
    @Override public void run() {
      while (true) {
        long waitNanos = cleanup(System.nanoTime());
        if (waitNanos == -1) return;
        if (waitNanos > 0) {
          long waitMillis = waitNanos / 1000000L;
          waitNanos -= (waitMillis * 1000000L);
          synchronized (ConnectionPool.this) {
            try {
              ConnectionPool.this.wait(waitMillis, (int) waitNanos);
            } catch (InterruptedException ignored) {
            }
          }
        }
      }
    }
  };

  private final Deque<RealConnection> connections = new ArrayDeque<>();
  final RouteDatabase routeDatabase = new RouteDatabase();
  boolean cleanupRunning;

```

- maxIdleConnections 最大保持连接数，这个数主要用于清理，实际的线程队列长度可能超过这个数。没当请求重新打开一个连接时，这个连接就会被加入队列。
- keepAliveDurationNs 连接最大保持时间
- cleanupRunnable 连接队列清理任务
- connections 连接保持队列
- routeDatabase 路由点存储，这个跟连接池没关系，主要是为了让所有连接都复用这一组路由数据
- cleanupRunning 清理线程是否在运行

ConnectionPool类负责控制Socket连接的复用，要了解整个流程首先要说明一下OkHttp对socket链接的封装Connection接口和其实现RealConnection：

> 根据HTTP2和websocket的协议，一个Socket连接可以承载多个流([多路复用[1.6]](#http_rfc6))。所以在OkHttp的实现中，用Connection代表一个Socket连接，用StreamAllocation代表连接内部的数据流。一个Connection中可以存在多个StreamAllocation。而ConnectionPool负责保存Connection和判断一个新的StreamAllocation能否添加到当期已有的Connection中。

我们通过流程图和源码来说明这个过程：

> 在这里我们仅关注ConnectionPool中的逻辑，其中有一些涉及Connection的函数我们仅做功能描述。

我们首先看一下几个主要函数
**获取一个连接:**
``` java
  /**
   * Returns a recycled connection to {@code address}, or null if no such connection exists. The
   * route is null if the address has not yet been routed.
   */
  RealConnection get(Address address, StreamAllocation streamAllocation, Route route) {
    assert (Thread.holdsLock(this));
    for (RealConnection connection : connections) {
      if (connection.isEligible(address, route)) {
        streamAllocation.acquire(connection);
        return connection;
      }
    }
    return null;
  }
```
我们可以通过当前请求生成的地址信息([Address/Route [2]](#[2]))获取一个连接，Connection通过isEligible函数判断当前连接是否可以继续添加一个流，如果可以添加，就将streamAllocation和Connection绑定，此时请求才真正的连接到服务器。

**合并连接**
```java
/**
   * Replaces the connection held by {@code streamAllocation} with a shared connection if possible.
   * This recovers when multiple multiplexed connections are created concurrently.
   */
  Socket deduplicate(Address address, StreamAllocation streamAllocation) {
    assert (Thread.holdsLock(this));
    for (RealConnection connection : connections) {
      if (connection.isEligible(address, null)
          && connection.isMultiplexed()
          && connection != streamAllocation.connection()) {
        return streamAllocation.releaseAndAcquire(connection);
      }
    }
    return null;
  }
```
这个函数主要用于清理重复的连接。在HTTP2协议中，一个连接可以承载多个请求，当多个请求同时发起时，因为多线程同步问题，可能都没有查询到有可用的连接，此时会创建多个连接。所以当连接创建完并且添加到连接池后，针对当前请求，会再次在连接池在连接池中搜索一次，如果有相同的连接，则释放掉当前连接，将请求接入到已有的连接中。

**清理连接**
我们再来看一下连接队列的清理流程：
![ ](/images/OkHttp连接池清理流程.png)

一共有两个地方可以触发清理逻辑：

- 添加一个新的连接到连接保持队列
- 某个连接中所有流都结束时，会主动调用连接池中的connectionBecameIdle函数

当触发清理逻辑后，队列将逐渐恢复到允许的大小，并且清理超时的连接。

---

以上便是OkHttp对外开放接口和非协议相关功能逻辑的主要接口，在下一章，我们将深入OkHttp内部来分析OkHttp的原理和框间结构。

## 参考资料
- <span id="[1]">[1]</span> [OkHttp官方文档](https://github.com/square/okhttp/wiki)
- <span id="[2]">[2]</span> [一个比较好的翻译](http://www.jianshu.com/p/2b44343a9bca)

