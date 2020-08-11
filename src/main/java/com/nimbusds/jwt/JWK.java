package com.nimbusds.jwt;

import java.text.ParseException;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;

/**
 * The base abstract class for JSON Web Keys (JWKs).
 *
 * <p>This is a JSON object that represents a single public key.
 *
 * <p>The following members are common to all key types:
 *
 * <ul> <li>alg (required) <li>use (optional) <li>kid (optional) </ul>
 *
 * <p>Example JWK (of the Elliptic Curve type):
 *
 * <pre>
 * {
 *   "alg" : "EC",
 *   "crv" : "P-256",
 *   "x"   : "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 *   "y"   : "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 *   "use" : "enc",
 *   "kid" : "1"
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
public abstract class JWK {

    /**
     * Enumeration of the supported {@link JWK} algorithm families.
     */
    public static enum AlgorithmFamily {

        /**
         * Elliptic Curve.
         */
        EC,
        /**
         * RSA.
         */
        RSA;
    }

    /**
     * Enumeration of the supported {@link JWK} uses.
     */
    public static enum Use {

        /**
         * Signature ({@code sig}).
         */
        SIGNATURE("sig"),
        /**
         * Encryption ({@code enc}).
         */
        ENCRYPTION("enc");
        /**
         * The canonical use value.
         */
        private String value;

        /**
         * Creates a new JWK use with the specified canonical value.
         *
         * @param value The canonical use value.
         */
        private Use(final String value) {

            this.value = value;
        }

        /**
         * Returns the canonical string representation of this JWK use.
         *
         * @return The canonical string representation.
         */
        public String toString() {

            return value;
        }

        /**
         * Parses the specified JWK use string.
         *
         * @param s The canonical string representation. Must not be
         * {@code null}.
         *
         * @return The JWK use.
         *
         * @throws ParseException If the string could't be parsed to a valid key
         * use.
         */
        public static Use parse(final String s)
                throws ParseException {

            if (s.equals("sig")) {
                return SIGNATURE;
            } else if (s.equals("enc")) {
                return ENCRYPTION;
            } else {
                throw new ParseException("Couldn't parse JWK Key Object use: " + s, 0);
            }
        }
    }
    /**
     * The algorithm family, mandatory.
     */
    private final AlgorithmFamily alg;
    /**
     * The use, optional.
     */
    private final Use use;
    /**
     * The key ID, optional.
     */
    private final String kid;

    /**
     * Creates a new Json Web Key (JWK) with the specified parameters.
     *
     * @param alg The algorithm family. Must not be {@code null}.
     * @param use The use. {@code null} if not specified or if the key is
     * intended for signatures as well as encryption.
     * @param kid The key ID. {@code null} if not specified.
     */
    public JWK(final AlgorithmFamily alg, final Use use, final String kid) {

        if (alg == null) {
            throw new NullPointerException("The algorithm family \"alg\" must not be null");
        }

        this.alg = alg;

        this.use = use;

        this.kid = kid;
    }

    /**
     * Gets the algorithm family ({@code alg}) of this JWK.
     *
     * @return The algorithm family.
     */
    public AlgorithmFamily getAlgorithmFamily() {

        return alg;
    }

    /**
     * Gets the use ({@code use}) of this JWK.
     *
     * @return The use, {@code null} if not specified or if the key is intended
     * for signatures as well as for encryption.
     */
    public Use getUse() {

        return use;
    }

    /**
     * Gets the ID ({@code kid}) of this JWK. The key ID can be used to match a
     * specific key. This can be used, for instance, to choose among a set of
     * keys within the JWK during key rollover. The key ID may also correspond
     * to a JWS "kid" value.
     *
     * @return The key ID, {@code null} if not specified.
     */
    public String getKeyID() {

        return kid;
    }

    /**
     * Returns a JSON object representation of this JWK (only the common members
     * will be included). This method is intended to be called from extending
     * classes.
     *
     * <p>Example:
     *
     * <pre>
     * {
     *   "alg" : "RSA",
     *   "use" : "sig",
     *   "kid" : "fd28e025-8d24-48bc-a51a-e2ffc8bc274b"
     * }
     * </pre>
     *
     * @return The JSON object representation.
     */
    public JSONObject toJSONObject() {

        JSONObject o = new JSONObject();

        o.put("alg", alg.toString());

        if (use != null) {
            o.put("use", use.toString());
        }

        if (kid != null) {
            o.put("kid", kid);
        }

        return o;
    }

    /**
     * Returns the JSON object string representation of this JWK.
     *
     * @return The JSON object string representation.
     */
    public String toString() {

        return toJSONObject().toString();
    }

    /**
     * Parses a JWK from the specified JSON object string representation. The
     * JWK must be an {@link ECKey} or an {@link RSAKey}.
     *
     * @param s The JSON object string to parse. Must not be {@code null}.
     *
     * @return The JWK.
     *
     * @throws JWKException If the string couldn't be parsed to valid and
     * supported JWK.
     */
    public static JWK parse(final String s)
            throws JWKException {

        if (s == null) {
            throw new NullPointerException("The JSON object string must not be null");
        }

        try {
            JSONParser parser = new JSONParser(JSONParser.MODE_RFC4627);

            return parse((JSONObject) parser.parse(s));

        } catch (net.minidev.json.parser.ParseException e) {

            throw new JWKException("Invalid JSON: " + e.getMessage(), e);

        } catch (ClassCastException e) {

            throw new JWKException("The top level JSON entity must be an object");
        }
    }

    /**
     * Parses a JWK from the specified JSON object representation. The JWK must
     * be an {@link ECKey} or an {@link RSAKey}.
     *
     * @param jsonObject The JSON object to parse. Must not be {@code null}.
     *
     * @return The JWK.
     *
     * @throws JWKException If the JSON object couldn't be parsed to a valid and
     * supported JWK.
     */
    public static JWK parse(final JSONObject jsonObject)
            throws JWKException {

        if (jsonObject == null) {
            throw new NullPointerException("The JSON object must not be null");
        }


        if (jsonObject.get("alg") == null
                || !(jsonObject.get("alg") instanceof String)) {
            throw new JWKException("The algorithm family \"alg\" must be a string");
        }

        AlgorithmFamily alg = null;

        try {
            alg = AlgorithmFamily.valueOf((String) jsonObject.get("alg"));

        } catch (IllegalArgumentException e) {

            throw new JWKException("Invalid or unsupported algorithm family \"alg\": " + (String) jsonObject.get("alg"), e);
        }

        switch (alg) {

            case EC:
                return ECKey.parse(jsonObject);

            case RSA:
                return RSAKey.parse(jsonObject);

            default:
                throw new JWKException("Invalid or unsupported algorithm family \"alg\": " + alg);
        }
    }
}
