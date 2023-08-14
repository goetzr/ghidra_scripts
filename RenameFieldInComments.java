//Renames a variable name in the comments of the current selection.
//@author Russ Goetz
//@category Comments
//@keybinding ctrl alt F2
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
import java.util.stream.*;

public class RenameFieldInComments extends RenameIdentifierInComments {
	
	private List<String> varNames;
	private String oldName;
	private String newName;
	
	private static final String DOT_ACCESS = ".";
	private static final String ARROW_ACCESS = "->";

	@Override
	protected boolean promptUserForInfo() {
		String varNamesStr = getString("Variable Names", "Enter comma-separated list of variables whose fields should be renamed:");
		if (varNamesStr == null) {
			return false;
		}
		varNames = getVariableNames(varNamesStr);
		
		oldName = getIdentifier("Field To Rename", "Enter field to rename:");
		if (oldName == null) {
			return false;
		}
		newName = getIdentifier("New Field Name", "Enter new field name:");
		if (newName == null) {
			return false;
		}
		return true;
	}
	
	@Override
	protected String renameInText(String text) {
		Iterator<String> varNamesIter = varNames.iterator();
		while (varNamesIter.hasNext()) {
			String varName = varNamesIter.next();
			int pos = 0;
			while (true) {
				// Search for the next occurrence of the variable name.
				int foundVarPos = findNextIdentifier(text, pos, varName);
				if (foundVarPos == -1) {
					// Didn't find the variable name.
					// Move on to the next variable name.
					break;
				}
				// Found the variable name. Skip past it.
				pos = foundVarPos + varName.length();
				
				// A field access operator should immediately follow the variable name.
				String fieldAccessOp = getFieldAccessOperator(text, pos);
				if (fieldAccessOp == null) {
					// A field access operator did not immediately follow the variable name.
					// Keep searching for the current variable name after this occurrence.
					continue;
				}
				// Found a field access operator immediately after the variable name. Skip past it.
				pos += fieldAccessOp.length();
				
				// The old field name should immediately follow the field access operator.
				int foundFieldPos = findNextIdentifier(text, pos, oldName);
				if (foundFieldPos == -1 || foundFieldPos != pos) {
					// The old field name was not found, or
					// the old field name did not immediately following the field access operator.
					// Keep searching for the current variable name after the field access operator.
					continue;
				}
				// Found the old field name immediately after the field access operator.
				// Replace it with the new field name.
				text = text.substring(0, foundFieldPos) + newName + text.substring(foundFieldPos + oldName.length());
				
				// Keep searching for the current variable name after the replaced field name. 
				pos += newName.length();
			}
		}
		return text;
	}
	
	private String getFieldAccessOperator(String text, int pos) {
		// A field access operator is "." or "->".
		if (stringAtPosition(text, pos, DOT_ACCESS)) {
			return DOT_ACCESS;
		} else if (stringAtPosition(text, pos, ARROW_ACCESS)) {
			return ARROW_ACCESS;
		} else {
			return null;
		}
	}
	
	private boolean stringAtPosition(String text, int pos, String str) {
		return pos + str.length() < text.length() &&
				text.substring(pos, pos + str.length()).equals(str);
	}
	
	private String getString(String title, String message) {
		try {
			String str = askString(title, message);
			return str;
		} catch (CancelledException e) {
			return null;
		}
	}
	
	private List<String> getVariableNames(String varNamesStr) {
		return Arrays.asList(varNamesStr.split(",")).stream()
				.map((varName) -> varName.trim())
				.filter((varName) -> !varName.isEmpty())
				.collect(Collectors.toList());
	}
	
	/*
	 * =============================================================================================
	 * Tests
	 * =============================================================================================
	 */
	@Override
	protected void runDerivedTests() {
		test_renameInText();
		test_getVariableNames();
	}
	
	private void test_renameInText() {
		// Found.
		varNames = Arrays.asList(new String[] { "var1" });
		oldName = "field_0x8";
		newName = "ref_count";
		assertEqual(renameInText("var1.field_0x8"), "var1.ref_count");
		assertEqual(renameInText("var1->field_0x8"), "var1->ref_count");
		assertEqual(renameInText("var1.field_0x8\nvar2.field_0x8"), "var1.ref_count\nvar2.field_0x8");
		assertEqual(renameInText("var1->field_0x8\nvar2->field_0x8"), "var1->ref_count\nvar2->field_0x8");
		assertEqual(renameInText("var2.field_0x8\nvar1.field_0x8"), "var2.field_0x8\nvar1.ref_count");
		assertEqual(renameInText("var1->field_0x8, var2->field_0x8\nvar1->field_0x8"), "var1->ref_count, var2->field_0x8\nvar1->ref_count");
		
		varNames = Arrays.asList(new String[] { "var1", "var2" });
		assertEqual(renameInText("var1->field_0x8, var1.field_0x8"), "var1->ref_count, var1.ref_count");
		assertEqual(renameInText("var2->field_0x8, var2.field_0x8"), "var2->ref_count, var2.ref_count");
		assertEqual(renameInText("var1->field_0x8, var2.field_0x8"), "var1->ref_count, var2.ref_count");
		assertEqual(renameInText("var1.field_0x8\nvar2->field_0x8"), "var1.ref_count\nvar2->ref_count");
		assertEqual(renameInText("var1->field_0x8, var2.field_0x8\nvar1.field_0x8, var2->field_0x8"), "var1->ref_count, var2.ref_count\nvar1.ref_count, var2->ref_count");
		
		// Not found.
		varNames = Arrays.asList(new String[] { "var1" });
		assertEqual(renameInText("var2.field_0x8"), "var2.field_0x8");
		assertEqual(renameInText("var1>field_0x8"), "var1>field_0x8");
		assertEqual(renameInText("myvar1.field_0x8"), "myvar1.field_0x8");
		assertEqual(renameInText("var1_yours.field_0x8"), "var1_yours.field_0x8");
		assertEqual(renameInText("var1.field_0x8_double"), "var1.field_0x8_double");
		assertEqual(renameInText("var1.int_field_0x8"), "var1.int_field_0x8");
		assertEqual(renameInText("var1.int_field_0x8_2"), "var1.int_field_0x8_2");
		assertEqual(renameInText("not var1. field_0x8 is the culprit"), "not var1. field_0x8 is the culprit");
		assertEqual(renameInText("var1 -> field_0x8 is an integer"), "var1 -> field_0x8 is an integer");
	}
	
	private void test_getVariableNames() {
		assertEqual(getVariableNames("var1"), Arrays.asList(new String[] { "var1" }));
		assertEqual(getVariableNames("var1,"), Arrays.asList(new String[] { "var1" }));
		assertEqual(getVariableNames(",var1"), Arrays.asList(new String[] { "var1" }));
		assertEqual(getVariableNames(",var1,"), Arrays.asList(new String[] { "var1" }));
		assertEqual(getVariableNames("var1,var2"), Arrays.asList(new String[] { "var1", "var2" }));
		assertEqual(getVariableNames(" var1 ,  var2  "), Arrays.asList(new String[] { "var1", "var2" }));
		assertEqual(getVariableNames("var1,var2,var3"), Arrays.asList(new String[] { "var1", "var2", "var3" }));
	}
	
	private static void assertEqual(String a, String b) throws AssertionError {
		if (!a.equals(b)) {
			throw new AssertionError();
		}
	}
	
	private static void assertEqual(List<String> a, List<String> b) throws AssertionError {
		if (a.size() != b.size()) {
			throw new AssertionError();
		}
		
		for (int i = 0; i < a.size(); ++i) {
			if (!a.get(i).equals(b.get(i))) {
				throw new AssertionError();
			}
		}
	}
}