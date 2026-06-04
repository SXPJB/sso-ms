package com.fsociety.auth.sso.ms

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class Application

fun main(args: Array<String>) {
    runApplication<com.fsociety.auth.sso.ms.Application>(*args)
}
