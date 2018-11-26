package no.difi.oauth2.utils;

public class Args {

    String env;

    String props;

    String pid;

    boolean commfides;

    public String getEnv() {
        return env;
    }

    public void setEnv(String env) {
        this.env = env;
    }

    public String getProps() {
        return props;
    }

    public void setProps(String props) {
        this.props = props;
    }

    public String getPid() {
        return pid;
    }

    public void setPid(String pid) {
        this.pid = pid;
    }

    public boolean isCommfides() {
        return commfides;
    }

    public void setCommfides(boolean commfides) {
        this.commfides = commfides;
    }

    public static Args fromArgs(String[] args) {
        Args a = new Args();

        if (args == null || args.length == 0) {
            return a;
        }

        switch (args[0]) {
            case "--props":
                a.setProps(args[1]);
                break;
            case "--env":
                a.setEnv(args[1]);
                break;
            case "--pid":
                a.setPid(args[1]);
                break;
            case "--commfides":
                a.setCommfides(true);
                break;
            default:
                System.out.println("usage:\n java -jar <jarfile> [--pid <pid>] or\n java -jar <jarfile> --env test1|yt2|ver2|atest|systest [--pid <pid>] or\n java -jar <jarfile> --props <path.to.props.file> [--pid <pid>]");
                System.exit(0);
        }

        if (args.length<=2) {
            return a;
        }

        switch (args[2]) {
            case "--pid":
                a.setPid(args[3]);
                break;
            case "--commfides":
                a.setCommfides(true);
                break;
            default:
                System.out.println("usage: java -jar <jarfile> --env test1|yt2|ver2 [--pid <pid>] or java -jar <jarfile> --props <path.to.props.file> [--pid <pid>]");
                System.exit(0);
        }

        return a;
    }
}
