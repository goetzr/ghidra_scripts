//Abstract base class for scripts that rename identifiers in the comments of the current selection.

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

public abstract class RSG_RenameIdentifierInComments extends GhidraScript {

	protected static final String INVALID_IDENTIFIER_MSG = "You must enter a valid identifier.\n" +
			"A valid identifier must start with a letter or an underscore.\n" +
			"If it starts with an underscore, the next character must be a letter.\n" +
			"All remaining characters must be letters, digits, or underscores.";

	protected static final String INVALID_IDENTIFIER_TITLE = "Invalid Identifier";

	protected Listing listing;

	protected abstract boolean promptUserForInfo();

	protected abstract String renameInText(String text);

	protected abstract void runDerivedTests();

	@Override
	protected void run() throws Exception {
		// runTests();
		// return;

		listing = currentProgram.getListing();

		if (currentSelection == null) {
			JOptionPane.showMessageDialog(
					null,
					"You must select the area where the rename should occur.",
					"No Selection",
					JOptionPane.ERROR_MESSAGE);
			return;
		}

		if (!promptUserForInfo()) {
			return;
		}

		AddressIterator selectionAddrIter = currentSelection.getAddresses(true);
		while (selectionAddrIter.hasNext()) {
			Address addr = selectionAddrIter.next();
			renameInComments(addr);
		}
	}

	private void renameInComments(Address addr) {
		// Plate comment.
		String plateComment = listing.getComment(CodeUnit.PLATE_COMMENT, addr);
		if (plateComment != null) {
			plateComment = renameInText(plateComment);
			listing.setComment(addr, CodeUnit.PLATE_COMMENT, plateComment);
		}

		// Pre comment.
		String preComment = listing.getComment(CodeUnit.PRE_COMMENT, addr);
		if (preComment != null) {
			preComment = renameInText(preComment);
			listing.setComment(addr, CodeUnit.PRE_COMMENT, preComment);
		}

		// EOL comment.
		String eolComment = listing.getComment(CodeUnit.EOL_COMMENT, addr);
		if (eolComment != null) {
			eolComment = renameInText(eolComment);
			listing.setComment(addr, CodeUnit.EOL_COMMENT, eolComment);
		}

		// Post comment.
		String postComment = listing.getComment(CodeUnit.POST_COMMENT, addr);
		if (postComment != null) {
			postComment = renameInText(postComment);
			listing.setComment(addr, CodeUnit.POST_COMMENT, postComment);
		}
	}

	protected int findNextIdentifier(String text, int startPos, String id) {
		int pos = startPos;

		while (true) {
			if (pos >= text.length()) {
				// The identifier was not found yet and there's no more text available.
				return -1;
			}

			int idPos = text.indexOf(id, pos);
			if (idPos == -1) {
				// The identifier was not found.
				return -1;
			}

			// Ensure that id is not a substring of a longer identifier.
			// =========================================================
			int endIdPos = idPos + id.length();

			// Ensure that id is not the start of a longer identifier or in the middle of a
			// longer identifier.
			// If it is, resume searching after the longer identifier.
			if (endIdPos < text.length()) {
				int trailingPos = endIdPos;
				int trailingChar = text.charAt(trailingPos);
				while (RSG_IdentifierUtils.isTrailingIdentifierChar(trailingChar)) {
					++trailingPos;
					if (trailingPos >= text.length()) {
						// id is the start of a longer identifier or in the middle of a
						// longer identifier at the end of the text.
						return -1;
					}
					trailingChar = text.charAt(trailingPos);
				}

				if (trailingPos != endIdPos) {
					// id is the start of a longer identifier or in the middle of a longer
					// identifier.
					// Continue searching after the longer identifier.
					pos = trailingPos;
					continue;
				}
			}

			// id is not the start of a longer identifier or in the middle of a longer
			// identifier.
			// Ensure that id is not the end of a longer identifier.
			if (idPos > 0 && RSG_IdentifierUtils.isTrailingIdentifierChar(text.charAt(idPos - 1))) {
				// id is the end of a longer identifier.
				// Continue searching after id.
				pos = endIdPos;
				continue;
			}

			return idPos;
		}
	}

	protected String getIdentifier(String title, String message) {
		try {
			String id = askString(title, message);
			while (!RSG_IdentifierUtils.isIdentifier(id)) {
				JOptionPane.showMessageDialog(
						null,
						INVALID_IDENTIFIER_MSG,
						INVALID_IDENTIFIER_TITLE,
						JOptionPane.ERROR_MESSAGE);
				id = askString(message, title);
			}
			return id;
		} catch (CancelledException e) {
			return null;
		}
	}

	/*
	 * =============================================================================
	 * ================
	 * Tests
	 * =============================================================================
	 * ================
	 */
	private void runTests() {
		RSG_IdentifierUtils.runTests();
		test_findNextIdentifier();
		runDerivedTests();
	}

	private void test_findNextIdentifier() {
		// Found.
		assertEqual(findNextIdentifier("xx", 0, "xx"), 0);
		assertEqual(findNextIdentifier("y = 7, xx", 0, "xx"), 7);
		assertEqual(findNextIdentifier("y = 7, xx = 5, z = 8", 0, "xx"), 7);
		assertEqual(findNextIdentifier("++xx, xx = 5", 4, "xx"), 6);
		assertEqual(findNextIdentifier("yy+xx=7", 0, "xx"), 3);

		// Not found.
		assertEqual(findNextIdentifier("yy = 5", 0, "xx"), -1);
		assertEqual(findNextIdentifier("xxy = 5", 0, "xx"), -1);
		assertEqual(findNextIdentifier("zxx = 5", 0, "xx"), -1);
		assertEqual(findNextIdentifier("zxxy = 5", 0, "xx"), -1);
		assertEqual(findNextIdentifier("yy+xxx=7", 0, "xx"), -1);
		assertEqual(findNextIdentifier("yy+xxx", 0, "xx"), -1);
		assertEqual(findNextIdentifier("yy+xx2=7", 0, "xx"), -1);
		assertEqual(findNextIdentifier("yy+xx_2=7", 0, "xx"), -1);
	}

	private static void assertEqual(int a, int b) throws AssertionError {
		if (a != b) {
			throw new AssertionError();
		}
	}
}