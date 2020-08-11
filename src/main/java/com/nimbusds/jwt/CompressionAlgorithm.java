package com.nimbusds.jwt;

import java.text.ParseException;

/**
 * Enumeration of the compression algorithms for JSON Web Encryption (JWE).
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-21)
 */
public enum CompressionAlgorithm {

    /**
     * DEFLATE Compressed Data Format Specification version 1.3, as described in
     * RFC 1951.
     */
    DEF("DEF"),
    /**
     * No compression is applied to the plaintext.
     */
    NONE("none");
    /**
     * The canonical algorithm name according to the JWE spec.
     */
    private String name;

    /**
     * Returns the canonical name of this compression algorithm.
     *
     * @return The canonical name of this compression algorithm.
     */
    public String getName() {

        return name;
    }

    /**
     * Parses the specified compression algorithm.
     *
     * @param name The canonical compression algorithm name. Must not be
     * {@code null}.
     *
     * @throws ParseException If the name is {@code null} of doesn't match a
     * compression algorithm name.
     */
    public static CompressionAlgorithm parse(final String name)
            throws ParseException {

        if (name == null) {
            throw new ParseException("The compression algorithm name must not be null", 0);
        }

        if (name.equals("DEF")) {
            return DEF;
        } else if (name.equals("none")) {
            return NONE;
        } else {
            throw new ParseException("Unknown compression algorithm: " + name, 0);
        }
    }

    /**
     * Creates a new compression algorithm with the specified name.
     *
     * @param name The algorithm name.
     */
    private CompressionAlgorithm(final String name) {

        this.name = name;
    }
}
