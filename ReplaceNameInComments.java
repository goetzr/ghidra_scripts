//Replaces a variable name in comments with a new name.
//@author Russ Goetz
//@category Personal
//@keybinding
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

public class ReplaceNameInComments extends GhidraScript {

	private static final String INVALID_VAR_NAME_MSG =
			"You must enter a valid variable name.\n" +
			"A valid variable name starts with a letter.\n" +
			"All remaining characters must be letters, digits, or underscores.";
	
	private static final String INVALID_VAR_NAME_TITLE = "Invalid Variable Name";
	
	private Listing listing;
	
	@Override
	protected void run() throws Exception {
		//runTests();
		//return;
		
		if (currentSelection == null) {
			JOptionPane.showMessageDialog(
					null,
					"You must select the area where the replacement should occur.",
					"No Selection",
			        JOptionPane.ERROR_MESSAGE
			);
			return;
		}
		
		String oldName = getVariableName("Variable Name To Replace", "Enter variable name to replace:");
		if (oldName == null) {
			return;
		}
		String newName = getVariableName("New Variable Name", "Enter new variable name:");
		if (newName == null) {
			return;
		}
		
		listing = currentProgram.getListing();
		
		AddressIterator selectionAddrIter = currentSelection.getAddresses(true);
		while (selectionAddrIter.hasNext()) {
			Address addr = selectionAddrIter.next();
			replaceInComments(addr, oldName, newName);
		}
	}
	
	private void replaceInComments(Address addr, String oldName, String newName) {
		// Plate comment.
		String plateComment = listing.getComment(CodeUnit.PLATE_COMMENT, addr);
		if (plateComment != null) {
			plateComment = replaceVariableName(plateComment, oldName, newName);
			listing.setComment(addr,  CodeUnit.PLATE_COMMENT, plateComment);
		}
		
		// Pre comment.
		String preComment = listing.getComment(CodeUnit.PRE_COMMENT, addr);
		if (preComment != null) {
			preComment = replaceVariableName(preComment, oldName, newName);
			listing.setComment(addr,  CodeUnit.PRE_COMMENT, preComment);
		}
				
		// EOL comment.
		String eolComment = listing.getComment(CodeUnit.EOL_COMMENT, addr);
		if (eolComment != null) {
			eolComment = replaceVariableName(eolComment, oldName, newName);
			listing.setComment(addr,  CodeUnit.EOL_COMMENT, eolComment);
		}
		
		// Post comment.
		String postComment = listing.getComment(CodeUnit.POST_COMMENT, addr);
		if (postComment != null) {
			postComment = replaceVariableName(postComment, oldName, newName);
			listing.setComment(addr,  CodeUnit.POST_COMMENT, postComment);
		}
	}
	
	private String replaceVariableName(String text, String oldName, String newName) {
		int pos = 0;
		while (true) {
			int foundPos = findNextVariableName(text, pos, oldName);
			if (foundPos == -1) {
				break;
			}
			int endPos = foundPos + oldName.length();
			text = text.substring(0, foundPos) + newName + text.substring(endPos);
			pos = foundPos + newName.length();
		}
		return text;
	}
	
	private int findNextVariableName(String text, int startPos, String name) {
		int pos = startPos;
		
		while (true) {
			if (pos >= text.length()) {
				// The name was not found yet and there's no more text available.
				return -1;
			}
			
			int namePos = text.indexOf(name, pos);
			if (namePos == -1) {
				// The name was not found.
				return -1;
			}
			
			int endNamePos = namePos + name.length();
			if (text.length() == endNamePos) {
				// The name was found at the end of the text.
				return namePos;
			}
			
			// Ensure that name is not a prefix to a longer variable name.
			// If it is, resume searching after the longer variable name.
			int longerPos = endNamePos;
			int longerChar = text.charAt(longerPos);
			while (isTrailingVariableNameChar(longerChar)) {
				++longerPos;
				if (longerPos >= text.length()) {
					// The name is a prefix to a longer variable name at the end of the text.
					return -1;
				}
				longerChar = text.charAt(longerPos);
			}
			
			if (longerPos == endNamePos) {
				// The name is not a prefix to a longer variable name.
				return namePos;
			}
			
			// The name is a prefix to a longer variable name.
			// Continue searching after the longer variable name.
			pos = longerPos;
		}
	}
	
	private String getVariableName(String title, String message) {
		try {
			String name = askString(title, message);
			while (!isVariableName(name)) {
				JOptionPane.showMessageDialog(
					null,
					INVALID_VAR_NAME_MSG,
					INVALID_VAR_NAME_TITLE,
			        JOptionPane.ERROR_MESSAGE
				);
				name = askString(message, title);
			}
			return name;
		} catch (CancelledException e) {
			return null;
		}
	}
	
	private boolean isVariableName(String str) {
		if (str.isEmpty()) {
			return false;
		}
		
		// First character must be a letter.
		int first = str.charAt(0);
		if (!Character.isLetter(first)) {
			return false;
		}
		
		// Remaining characters must be letters, digits, or underscores.
		return str.chars().skip(1).allMatch(c -> isTrailingVariableNameChar(c));
	}
	
	private boolean isTrailingVariableNameChar(int c) {
		// All characters after the first in a variable name must be letters, digits, or underscores.
		return Character.isLetter(c) || Character.isDigit(c) || c == '_';
	}
	
	/*
	 * =============================================================================================
	 * Tests
	 * =============================================================================================
	 */
	private void runTests() {
		test_isTrailingVariableNameChar();
		test_isVariableName();
		test_findNextVariableName();
		test_replaceVariableName();
	}
	
	private void test_replaceVariableName() {
		// Found.
		assertEqual(replaceVariableName("xx", "xx", "yy"), "yy");
		assertEqual(replaceVariableName("y = 7, xx", "xx", "yy"), "y = 7, yy");
		assertEqual(replaceVariableName("y = 7, xx = 5, z = 8", "xx", "yy"), "y = 7, yy = 5, z = 8");
		assertEqual(replaceVariableName("++xx, xx = 5", "xx", "yy"), "++yy, yy = 5");
		assertEqual(replaceVariableName("zz+xx=7", "xx", "yy"), "zz+yy=7");
		assertEqual(replaceVariableName("xx = 7\nzz = xx % 2\nwrite(xx)", "xx", "yy"), "yy = 7\nzz = yy % 2\nwrite(yy)");
		
		// Not found.
		assertEqual(replaceVariableName("yy = 5", "xx", "yy"), "yy = 5");
		assertEqual(replaceVariableName("xxx = 5", "xx", "yy"), "xxx = 5");
		assertEqual(replaceVariableName("yy+xxx=7", "xx", "yy"), "yy+xxx=7");
		assertEqual(replaceVariableName("yy+xxx", "xx", "yy"), "yy+xxx");
		assertEqual(replaceVariableName("yy+xx2=7", "xx", "yy"), "yy+xx2=7");
		assertEqual(replaceVariableName("yy+xx_2=7", "xx", "yy"), "yy+xx_2=7");
	}
	
	private void test_findNextVariableName() {
		// Found.
		assertEqual(findNextVariableName("xx", 0, "xx"), 0);
		assertEqual(findNextVariableName("y = 7, xx", 0, "xx"), 7);
		assertEqual(findNextVariableName("y = 7, xx = 5, z = 8", 0, "xx"), 7);
		assertEqual(findNextVariableName("++xx, xx = 5", 4, "xx"), 6);
		assertEqual(findNextVariableName("yy+xx=7", 0, "xx"), 3);
		
		// Not found.
		assertEqual(findNextVariableName("yy = 5", 0, "xx"), -1);
		assertEqual(findNextVariableName("xxx = 5", 0, "xx"), -1);
		assertEqual(findNextVariableName("yy+xxx=7", 0, "xx"), -1);
		assertEqual(findNextVariableName("yy+xxx", 0, "xx"), -1);
		assertEqual(findNextVariableName("yy+xx2=7", 0, "xx"), -1);
		assertEqual(findNextVariableName("yy+xx_2=7", 0, "xx"), -1);
	}
	
	private void test_isVariableName() {
		assertTrue(isVariableName("x"));
		assertTrue(isVariableName("x_"));
		assertTrue(isVariableName("x2"));
		assertTrue(isVariableName("xx2"));
		assertTrue(isVariableName("x_2"));
		assertTrue(isVariableName("x_y"));
		assertTrue(isVariableName("x_2y"));
		
		assertFalse(isVariableName("_"));
		assertFalse(isVariableName("2"));
		assertFalse(isVariableName("_x"));
		assertFalse(isVariableName("2x"));
		assertFalse(isVariableName("x+"));
		assertFalse(isVariableName("x)"));
		assertFalse(isVariableName("+x)"));
		assertFalse(isVariableName("(x)"));
	}
	
	private void test_isTrailingVariableNameChar() {
		for (int c = 'a'; c <= 'z'; ++c) {
			assertTrue(isTrailingVariableNameChar(c));
		}
		for (int c = 'A'; c <= 'Z'; ++c) {
			assertTrue(isTrailingVariableNameChar(c));
		}
		for (int c = '0'; c <= '9'; ++c) {
			assertTrue(isTrailingVariableNameChar(c));
		}
		assertTrue(isTrailingVariableNameChar('_'));
		
		assertFalse(isTrailingVariableNameChar('+'));
		assertFalse(isTrailingVariableNameChar('-'));
		assertFalse(isTrailingVariableNameChar('*'));
		assertFalse(isTrailingVariableNameChar('/'));
		assertFalse(isTrailingVariableNameChar('%'));
		assertFalse(isTrailingVariableNameChar('&'));
		assertFalse(isTrailingVariableNameChar('|'));
		assertFalse(isTrailingVariableNameChar('['));
		assertFalse(isTrailingVariableNameChar(']'));
		assertFalse(isTrailingVariableNameChar('{'));
		assertFalse(isTrailingVariableNameChar('}'));
		assertFalse(isTrailingVariableNameChar('='));
		assertFalse(isTrailingVariableNameChar('!'));
		assertFalse(isTrailingVariableNameChar('@'));
		assertFalse(isTrailingVariableNameChar('#'));
		assertFalse(isTrailingVariableNameChar('$'));
		assertFalse(isTrailingVariableNameChar('?'));
		assertFalse(isTrailingVariableNameChar('\''));
		assertFalse(isTrailingVariableNameChar('\\'));
		assertFalse(isTrailingVariableNameChar('"'));
		assertFalse(isTrailingVariableNameChar('`'));
		assertFalse(isTrailingVariableNameChar('~'));
		assertFalse(isTrailingVariableNameChar(','));
		assertFalse(isTrailingVariableNameChar(';'));
		assertFalse(isTrailingVariableNameChar('<'));
		assertFalse(isTrailingVariableNameChar('>'));
	}
	
	private static void assertTrue(boolean condition) throws AssertionError {
		if (!condition) {
			throw new AssertionError();
		}
	}
	
	private static void assertFalse(boolean condition) throws AssertionError {
		if (condition) {
			throw new AssertionError();
		}
	}
	
	private static void assertEqual(int a, int b) throws AssertionError {
		if (a != b) {
			throw new AssertionError();
		}
	}
	
	private static void assertEqual(String a, String b) throws AssertionError {
		if (!a.equals(b)) {
			throw new AssertionError();
		}
	}
}