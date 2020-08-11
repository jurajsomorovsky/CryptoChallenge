package com.nimbusds.jwt;

import net.minidev.json.JSONObject;

/**
 * RSA JSON Web Key (JWK) Key Object.
 *
 * <p>Example JSON:
 *
 * <pre>
 * {
 *   "alg" : "RSA",
 *   "mod" : "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
 *            4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZC
 *            iFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5
 *            w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZg
 *            nYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt
 *            -bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIq
 *            bw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
 *   "exp" : "AQAB",
 *   "kid" : "2011-04-29"
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
 * See also http://en.wikipedia.org/wiki/RSA_%28algorithm%29
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-21)
 */
public final class RSAKey extends JWK {

    /**
     * The modulus value for the RSA public key.
     */
    private final Base64URL mod;
    /**
     * The exponent value for the RSA public key.
     */
    private final Base64URL exp;

    /**
     * Creates a new RSA JSON Web Key (JWK) with the specified parameters.
     *
     * @param mod The the modulus value for the RSA public key. It is
     * represented as the Base64URL encoding of value's big endian
     * representation. Must not be {@code null}.
     * @param exp The the exponent value for the RSA public key. It is
     * represented as the Base64URL encoding of value's big endian
     * representation. Must not be {@code null}.
     * @param use The use. {@code null} if not specified.
     * @param kid The key ID. {@code null} if not specified.
     */
    public RSAKey(final Base64URL mod, final Base64URL exp,
            final Use use, final String kid) {

        super(JWK.AlgorithmFamily.RSA, use, kid);

        if (mod == null) {
            throw new NullPointerException("The modulus value must not be null");
        }

        this.mod = mod;

        if (exp == null) {
            throw new NullPointerException("The exponent value must not be null");
        }

        this.exp = exp;
    }

    /**
     * Returns the modulus value for the RSA public key. It is represented as
     * the Base64URL encoding of the value's big ending representation.
     *
     * @return The RSA public key modulus.
     */
    public Base64URL getModulus() {

        return mod;
    }

    /**
     * Returns the exponent value for the RSA public key. It is represented as
     * the Base64URL encoding of the value's big ending representation.
     *
     * @return The RSA public key exponent.
     */
    public Base64URL getExponent() {

        return exp;
    }

    /**
     * @inheritDoc
     */
    public JSONObject toJSONObject() {

        JSONObject o = super.toJSONObject();

        // Append RSA public key specific attributes
        o.put("mod", mod.toString());
        o.put("exp", exp.toString());

        return o;
    }

    /**
     * Parses an RSA JWK from the specified JSON object representation.
     *
     * @param jsonObject The JSON object to parse. Must not be {@code null}.
     *
     * @return The RSA Key.
     *
     * @throws JWKException If the JSON object couldn't be parsed to valid RSA
     * JWK.
     */
    public static RSAKey parse(final JSONObject jsonObject)
            throws JWKException {

        if (jsonObject == null) {
            throw new NullPointerException("The JSON object must not be null");
        }

        // Parse the mandatory parameters first

        if (jsonObject.get("mod") == null || !(jsonObject.get("mod") instanceof String)) {
            throw new JWKException("Missing, null or non-string \"mod\" member");
        }

        if (jsonObject.get("exp") == null || !(jsonObject.get("exp") instanceof String)) {
            throw new JWKException("Missing, null or non-string \"exp\" member");
        }

        Base64URL mod = new Base64URL((String) jsonObject.get("mod"));
        Base64URL exp = new Base64URL((String) jsonObject.get("exp"));


        // Get optional "use"
        JWK.Use use = null;

        if (jsonObject.get("use") != null) {

            if (!(jsonObject.get("use") instanceof String)) {
                throw new JWKException("The \"use\" member must be a string");
            }

            String useStr = (String) jsonObject.get("use");

            if (useStr.equals("sig")) {
                use = JWK.Use.SIGNATURE;
            } else if (useStr.equals("enc")) {
                use = JWK.Use.ENCRYPTION;
            } else {
                throw new JWKException("Invalid or unsupported key use \"use\", must be \"sig\" or \"enc\"");
            }
        }


        // Get optional key ID
        String keyID = null;

        if (jsonObject.get("kid") != null) {

            if (!(jsonObject.get("kid") instanceof String)) {
                throw new JWKException("The \"kid\" member must be a string");
            }

            keyID = (String) jsonObject.get("kid");
        }

        return new RSAKey(mod, exp, use, keyID);
    }
}
