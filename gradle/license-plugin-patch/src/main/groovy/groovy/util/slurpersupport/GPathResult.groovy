package groovy.util.slurpersupport

class GPathResult {
    private final groovy.xml.slurpersupport.GPathResult delegate

    GPathResult(groovy.xml.slurpersupport.GPathResult delegate) {
        this.delegate = delegate
    }

    def propertyMissing(String name) {
        delegate.getProperty(name)
    }
}
