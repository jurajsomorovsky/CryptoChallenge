/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.cryptochallenge.handlers;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class IndexHandler extends PageHandler {

    public static final String FILE_NAME = "index.html";

    public IndexHandler() {
        fileName = FILE_NAME;
        page = readPage();
    }
}
