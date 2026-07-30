/**
 * 适配器：HTTP 投影、persistence 与控制面 store 委托（P1-08）。
 *
 * <p>可依赖 application port 与基础设施。新适配器不得引入
 * {@code control → analysis.parser} 反向依赖。
 */
package com.aq.jvmsentinel.adapter;
