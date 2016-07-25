package jm.desprez

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import io.jsonwebtoken.*
import io.jsonwebtoken.impl.crypto.EllipticCurveProvider
import javaslang.control.Try
import java.lang.reflect.Type
import java.security.KeyPair
import java.util.*
import java.util.Base64.Decoder
import java.util.Base64.Encoder

class JJWTDemo() {
    val key: KeyPair = EllipticCurveProvider.generateKeyPair()
    val payloadType: Type = object : TypeToken<MutableMap<String, Any>>() {}.type
    val encoder: Encoder = Base64.getEncoder()
    val decoder: Decoder = Base64.getDecoder()
    val gson = Gson()

    fun encode(sub: String, admin: Boolean = false): String = Jwts.builder()
            .setSubject(sub)
            .claim("admin", admin)
            .signWith(SignatureAlgorithm.ES512, key.private)
            .compact()

    fun decodePayload(token: String): MutableMap<String, Any> {
        val (header, payload, signature) = token.split('.')
        val payloadDecoded = String(decoder.decode(payload))
        return gson.fromJson(payloadDecoded, payloadType)
    }

    fun verify(token: String): Try<Jws<Claims>> = Try.of {
        Jwts.parser()
                .setSigningKey(key.public)
                .parseClaimsJws(token)
    }

    fun demo() {
        val compactJws = encode("Joe")

        val (header, payload, signature) = compactJws.split('.')

        verify(compactJws)
                .andThen { claims -> println(claims.body) }
                .onFailure { e -> println(e.message) }


        val fromJson = decodePayload(compactJws)
        fromJson["admin"] = true
        val forgedPayload = String(encoder.encode(gson.toJson(fromJson).toByteArray()))
        println(forgedPayload)
        val forgedToken = "$header.$forgedPayload.$signature"
        println(forgedToken)

        verify(forgedToken)
                .andThen { claims -> println(claims.body) }
                .onFailure { e -> println(e.message) }
    }
}

fun main(args: Array<String>) {
    JJWTDemo().demo()
}

