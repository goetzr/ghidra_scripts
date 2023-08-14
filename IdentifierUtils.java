class IdentifierUtils {
	
	public static boolean isIdentifier(String str) {
		if (str.isEmpty()) {
			return false;
		}
		
		int index = 0;
		
		// First character must be a letter or an underscore.
		int first = str.charAt(index);
		if (!Character.isLetter(first) && first != '_') {
			return false;
		}
		++index;
		
		// If the first character is an underscore, the second character must be a letter.
		if (first == '_') {
			if (str.length() == 1) {
				// A single '_' is not a valid name.
				return false;
			}
			int second = str.charAt(index);
			if (!Character.isLetter(second)) {
				return false;
			}
			++index;
		}
		
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
		
		assertFalse(isIdentifier("2"));
		assertFalse(isIdentifier("2x"));
		assertFalse(isIdentifier("x+"));
		assertFalse(isIdentifier("x)"));
		assertFalse(isIdentifier("+x)"));
		assertFalse(isIdentifier("(x)"));
		assertFalse(isIdentifier("_"));
		assertFalse(isIdentifier("_4"));
		assertFalse(isIdentifier("_4x"));
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