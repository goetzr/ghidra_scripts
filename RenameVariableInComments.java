//Renames a variable name in the comments of the current selection.
//@author Russ Goetz
//@category Comments
//@keybinding ctrl alt F1
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

public class RenameVariableInComments extends RenameIdentifierInComments {

	private String oldName;
	private String newName;

	@Override
	protected boolean promptUserForInfo() {
		oldName = getIdentifier("Variable To Rename", "Enter variable to rename:");
		if (oldName == null) {
			return false;
		}
		newName = getIdentifier("New Variable Name", "Enter new variable name:");
		if (newName == null) {
			return false;
		}
		return true;
	}

	@Override
	protected String renameInText(String text) {
		int pos = 0;
		while (true) {
			int foundPos = findNextIdentifier(text, pos, oldName);
			if (foundPos == -1) {
				break;
			}
			text = text.substring(0, foundPos) + newName + text.substring(foundPos + oldName.length());
			pos = foundPos + newName.length();
		}
		return text;
	}

	/*
	 * =============================================================================
	 * ================
	 * Tests
	 * =============================================================================
	 * ================
	 */
	@Override
	protected void runDerivedTests() {
		test_renameInText();
	}

	private void test_renameInText() {
		// Found.
		oldName = "xx";
		newName = "yy";
		assertEqual(renameInText("xx"), "yy");
		assertEqual(renameInText("y = 7, xx"), "y = 7, yy");
		assertEqual(renameInText("y = 7, xx = 5, z = 8"), "y = 7, yy = 5, z = 8");
		assertEqual(renameInText("++xx, xx = 5"), "++yy, yy = 5");
		assertEqual(renameInText("zz+xx=7"), "zz+yy=7");
		assertEqual(renameInText("xx = 7\nzz = xx % 2\nwrite(xx)"), "yy = 7\nzz = yy % 2\nwrite(yy)");

		// Not found.
		assertEqual(renameInText("yy = 5"), "yy = 5");
		assertEqual(renameInText("xxy = 5"), "xxy = 5");
		assertEqual(renameInText("zxx = 5"), "zxx = 5");
		assertEqual(renameInText("zxxy = 5"), "zxxy = 5");
		assertEqual(renameInText("yy+xxx=7"), "yy+xxx=7");
		assertEqual(renameInText("yy+xxx"), "yy+xxx");
		assertEqual(renameInText("yy+xx2=7"), "yy+xx2=7");
		assertEqual(renameInText("yy+xx_2=7"), "yy+xx_2=7");
	}

	private static void assertEqual(String a, String b) throws AssertionError {
		if (!a.equals(b)) {
			throw new AssertionError();
		}
	}
}