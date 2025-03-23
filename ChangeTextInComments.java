//Changes any text in the comments of the current selection.
//@author Russ Goetz
//@category Comments
//@keybinding ctrl alt F3
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.util.exception.*;

import java.util.*;

import javax.swing.*;

public class RSG_ChangeTextInComments extends GhidraScript {

    private Listing listing;

    @Override
    protected void run() throws Exception {
        listing = currentProgram.getListing();

        if (currentSelection == null) {
            JOptionPane.showMessageDialog(
                    null,
                    "You must select the area where the text change should occur.",
                    "No Selection",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }

        String oldText = getString("Text To Change", "Enter text to change:");
        if (oldText == null) {
            return;
        }
        String newText = getString("New Text", "Enter new text:");
        if (newText == null) {
            return;
        }

        AddressIterator selectionAddrIter = currentSelection.getAddresses(true);
        while (selectionAddrIter.hasNext()) {
            Address addr = selectionAddrIter.next();
            changeTextInComments(addr, oldText, newText);
        }
    }

    private String getString(String title, String message) {
        try {
            String str = askString(title, message);
            return str;
        } catch (CancelledException e) {
            return null;
        }
    }

    private void changeTextInComments(Address addr, String oldText, String newText) {
        // Plate comment.
        String plateComment = listing.getComment(CodeUnit.PLATE_COMMENT, addr);
        if (plateComment != null) {
            plateComment = changeTextInString(plateComment, oldText, newText);
            listing.setComment(addr, CodeUnit.PLATE_COMMENT, plateComment);
        }

        // Pre comment.
        String preComment = listing.getComment(CodeUnit.PRE_COMMENT, addr);
        if (preComment != null) {
            preComment = changeTextInString(preComment, oldText, newText);
            listing.setComment(addr, CodeUnit.PRE_COMMENT, preComment);
        }

        // EOL comment.
        String eolComment = listing.getComment(CodeUnit.EOL_COMMENT, addr);
        if (eolComment != null) {
            eolComment = changeTextInString(eolComment, oldText, newText);
            listing.setComment(addr, CodeUnit.EOL_COMMENT, eolComment);
        }

        // Post comment.
        String postComment = listing.getComment(CodeUnit.POST_COMMENT, addr);
        if (postComment != null) {
            postComment = changeTextInString(postComment, oldText, newText);
            listing.setComment(addr, CodeUnit.POST_COMMENT, postComment);
        }
    }

    private String changeTextInString(String str, String oldText, String newText) {
        int pos = 0;
        while (true) {
            int foundPos = findNextText(str, pos, oldText);
            if (foundPos == -1) {
                break;
            }
            str = str.substring(0, foundPos) + newText + str.substring(foundPos + oldText.length());
            pos = foundPos + newText.length();
        }
        return str;
    }

    protected int findNextText(String str, int startPos, String text) {
        if (startPos >= str.length()) {
            return -1;
        }
        return str.indexOf(text, startPos);
    }
}