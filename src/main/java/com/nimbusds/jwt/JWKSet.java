package com.nimbusds.jwt;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

/**
 * JSON Web Key (JWK) set, a JSON data structure that represents a set of
 * {@link JWK public JSON Web Keys (JWKs)}.
 *
 * <p>The JWK format is used to represent bare keys; representing certificate
 * chains is an explicit non-goal of the JWK specification. JSON Web Keys are
 * can be used in {@link JWS JSON Web Signature} (JWS) using the
 * {@link JWSHeader#getJWKURL "jku"} header parameter and in
 * {@link JWE JSON Web Encryption} (JWE) using the
 * {@link JWEHeader#getJWKURL "jku"} and
 * {@link JWEHeader#getEphemeralPublicKey "epk"} (Ephemeral Public Key) header
 * parameters.
 *
 * <p>Example JSON Web Key (JWK) set:
 *
 * <pre>
 * {"keys":
 *   [
 *     {"alg":"EC",
 *	"crv":"P-256",
 *	"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 *	"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 *	"use":"enc",
 *	"kid":"1"},
 *
 *     {"alg":"RSA",
 *	"mod": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
 * 4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs
 * tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2
 * QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI
 * SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb
 * w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
 *	"exp":"AQAB",
 *	"kid":"2011-04-29"}
 *   ]
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul> <li><a
 * href="http://tools.ietf.org/html/draft-ietf-jose-json-web-key-02">JWK draft
 * 02</a>. <li><a
 * href="http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-02">JWA
 * draft 02</a>. </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-21)
 */
public class JWKSet {

    /**
     * The JWK list.
     */
    private List<JWK> keys = new LinkedList<JWK>();

    /**
     * Creates a new empty JSON Web Key (JWK) set.
     */
    public JWKSet() {
        // Nothing to do
    }

    /**
     * Creates a new JSON Web Key (JWK) set with a single key.
     *
     * @param key The JWK. Must not be {@code null}.
     */
    public JWKSet(final JWK key) {

        if (key == null) {
            throw new NullPointerException("The JWK must not be null");
        }

        keys.add(key);
    }

    /**
     * Creates a new JSON Web Key (JWK) set with the specified keys.
     *
     * @param keys The JWK keys. Must not be {@code null}.
     */
    public JWKSet(final List<JWK> keys) {

        if (keys == null) {
            throw new NullPointerException("The JWK list must not be null");
        }

        this.keys.addAll(keys);
    }

    /**
     * Gets the keys (ordered) of this JSON Web Key (JWK) set.
     *
     * @return The keys, empty list if none.
     */
    public List<JWK> getKeys() {

        return keys;
    }

    /**
     * Returns a JSON object representation of this JSON Web Key (JWK) set.
     *
     * @return The JSON object representation.
     */
    public JSONObject toJSONObject() {

        JSONArray a = new JSONArray();

        Iterator<JWK> it = keys.iterator();

        while (it.hasNext()) {
            a.add(it.next().toJSONObject());
        }

        JSONObject o = new JSONObject();

        o.put("keys", a);

        return o;
    }

    /**
     * Returns the JSON object string representation of this JSON Web Key (JWK)
     * set.
     *
     * @return The JSON object string representation.
     */
    public String toString() {

        return toJSONObject().toString();
    }

    /**
     * Parses the specified string representing a JSON Web Key (JWK) set.
     *
     * @param s The string to parse. Must not be {@code null}.
     *
     * @return The JSON Web Key (JWK) set.
     *
     * @throws JWKException If the string couldn't be parsed to a valid and
     * supported JSON Web Key (JWK) set.
     */
    public static JWKSet parse(final String s)
            throws JWKException {

        if (s == null) {
            throw new NullPointerException("The parsed JSON string must not be null");
        }

        try {
            JSONParser parser = new JSONParser(JSONParser.MODE_RFC4627);

            return parse((JSONObject) parser.parse(s));

        } catch (ParseException e) {

            throw new JWKException("Invalid JSON: " + e.getMessage(), e);

        } catch (ClassCastException e) {

            throw new JWKException("The top level JSON entity must be an object");
        }
    }

    /**
     * Parses the specified JSON object representing a JSON Web Key (JWK) set.
     *
     * @param json The JSON object to parse. Must not be {@code null}.
     *
     * @return The JSON Web Key (JWK) set.
     *
     * @throws JWKException If the string couldn't be parsed to a valid and
     * supported JSON Web Key (JWK) set.
     */
    public static JWKSet parse(final JSONObject json)
            throws JWKException {

        if (json == null) {
            throw new NullPointerException("The JSON object must not be null");
        }

        if (!json.containsKey("keys") || json.get("keys") == null) {
            throw new JWKException("Missing or null \"keys\" member in the top level JSON object");
        }

        JSONArray keyArray = null;

        try {
            keyArray = (JSONArray) json.get("keys");

        } catch (ClassCastException e) {

            throw new JWKException("The \"keys\" member must be a JSON array");
        }

        List<JWK> keys = new LinkedList<JWK>();

        for (int i = 0; i < keyArray.size(); i++) {

            if (!(keyArray.get(i) instanceof JSONObject)) {
                throw new JWKException("The \"keys\" JSON array must contain JSON objects only");
            }

            JSONObject keyJSON = (JSONObject) keyArray.get(i);

            try {
                keys.add(JWK.parse(keyJSON));

            } catch (JWKException e) {

                throw new JWKException("Invalid or unsupported JWK at position " + i);
            }
        }

        return new JWKSet(keys);
    }
}
