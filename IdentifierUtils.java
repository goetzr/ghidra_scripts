class IdentifierUtils {
	
	public static boolean isIdentifier(String str) {
		if (str.isEmpty()) {
			return false;
		}
		
		// Any number of underscores may start.
		int index = 0;
		int next = str.charAt(index);
		while (next == '_') {
			++index;
			if (index >= str.length()) {
				// All underscores is not a valid identifier.
				return false;
			}
			next = str.charAt(index);
		}
		
		// The character immediately following any underscores must be a letter.
		if (!Character.isLetter(next)) {
			return false;
		}
		++index;
		
		// Remaining characters must be letters, digits, or underscores.
		return str.chars().skip(index).allMatch(c -> isTrailingIdentifierChar(c));
	}
	
	public static boolean isTrailingIdentifierChar(int c) {
		// All characters after the first must be letters, digits, or underscores.
		return Character.isLetter(c) || Character.isDigit(c) || c == '_';
	}
	
	/*
	 * =============================================================================================
	 * Tests
	 * =============================================================================================
	 */
	public static void runTests() {
		test_isIdentifier();
		test_isTrailingIdentifierChar();
	}
	
	private static void test_isIdentifier() {
		assertTrue(isIdentifier("x"));
		assertTrue(isIdentifier("x_"));
		assertTrue(isIdentifier("x2"));
		assertTrue(isIdentifier("xx2"));
		assertTrue(isIdentifier("x_2"));
		assertTrue(isIdentifier("x_y"));
		assertTrue(isIdentifier("x_2y"));
		assertTrue(isIdentifier("_x"));
		assertTrue(isIdentifier("_x4"));
		assertTrue(isIdentifier("__x4"));
		assertTrue(isIdentifier("___x4"));
		
		assertFalse(isIdentifier("2"));
		assertFalse(isIdentifier("2x"));
		assertFalse(isIdentifier("x+"));
		assertFalse(isIdentifier("x)"));
		assertFalse(isIdentifier("+x)"));
		assertFalse(isIdentifier("(x)"));
		assertFalse(isIdentifier("_"));
		assertFalse(isIdentifier("_4"));
		assertFalse(isIdentifier("_4x"));
		assertFalse(isIdentifier("___4x"));
	}
	
	private static void test_isTrailingIdentifierChar() {
		for (int c = 'a'; c <= 'z'; ++c) {
			assertTrue(isTrailingIdentifierChar(c));
		}
		for (int c = 'A'; c <= 'Z'; ++c) {
			assertTrue(isTrailingIdentifierChar(c));
		}
		for (int c = '0'; c <= '9'; ++c) {
			assertTrue(isTrailingIdentifierChar(c));
		}
		assertTrue(isTrailingIdentifierChar('_'));
		
		assertFalse(isTrailingIdentifierChar('+'));
		assertFalse(isTrailingIdentifierChar('-'));
		assertFalse(isTrailingIdentifierChar('*'));
		assertFalse(isTrailingIdentifierChar('/'));
		assertFalse(isTrailingIdentifierChar('%'));
		assertFalse(isTrailingIdentifierChar('&'));
		assertFalse(isTrailingIdentifierChar('|'));
		assertFalse(isTrailingIdentifierChar('['));
		assertFalse(isTrailingIdentifierChar(']'));
		assertFalse(isTrailingIdentifierChar('{'));
		assertFalse(isTrailingIdentifierChar('}'));
		assertFalse(isTrailingIdentifierChar('='));
		assertFalse(isTrailingIdentifierChar('!'));
		assertFalse(isTrailingIdentifierChar('@'));
		assertFalse(isTrailingIdentifierChar('#'));
		assertFalse(isTrailingIdentifierChar('$'));
		assertFalse(isTrailingIdentifierChar('?'));
		assertFalse(isTrailingIdentifierChar('\''));
		assertFalse(isTrailingIdentifierChar('\\'));
		assertFalse(isTrailingIdentifierChar('"'));
		assertFalse(isTrailingIdentifierChar('`'));
		assertFalse(isTrailingIdentifierChar('~'));
		assertFalse(isTrailingIdentifierChar(','));
		assertFalse(isTrailingIdentifierChar(';'));
		assertFalse(isTrailingIdentifierChar('<'));
		assertFalse(isTrailingIdentifierChar('>'));
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
}