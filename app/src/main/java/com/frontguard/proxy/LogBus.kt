package com.frontguard.proxy

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList

object LogBus {
    private val listeners = CopyOnWriteArrayList<(String) -> Unit>()
    private val buffer = ArrayDeque<String>(300)
    private val sdf = SimpleDateFormat("HH:mm:ss", Locale.US)

    @Synchronized
    fun log(msg: String, level: String = "INFO") {
        val ts = sdf.format(Date())
        val line = "[$ts] [$level] $msg"
        if (buffer.size >= 300) {
            buffer.removeFirst()
        }
        buffer.addLast(line)
        for (l in listeners) {
            l(line)
        }
    }

    @Synchronized
    fun getHistory(): List<String> = buffer.toList()

    @Synchronized
    fun clear() {
        buffer.clear()
    }

    fun register(listener: (String) -> Unit) {
        listeners.add(listener)
    }

    fun unregister(listener: (String) -> Unit) {
        listeners.remove(listener)
    }
}
