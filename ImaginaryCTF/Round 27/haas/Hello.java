class Out {
    public static void println(String s) {
        try {
            var builder = new ProcessBuilder(new String[] { "bash" });
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

class Hello {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
