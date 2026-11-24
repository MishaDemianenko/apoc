package groovy.util

import groovy.util.slurpersupport.GPathResult
import org.xml.sax.ErrorHandler

/**
 * Groovy 4 moved XmlSlurper and GPathResult to groovy.xml, but the unmaintained license-report
 * plugin is compiled against the old locations. This class and GPathResult stand in for them,
 * covering only what the plugin calls.
 */
class XmlSlurper {
    private final groovy.xml.XmlSlurper delegate

    XmlSlurper(boolean validating, boolean namespaceAware) {
        delegate = new groovy.xml.XmlSlurper(validating, namespaceAware)
    }

    void setErrorHandler(ErrorHandler errorHandler) {
        delegate.setErrorHandler(errorHandler)
    }

    GPathResult parse(File file) {
        new GPathResult(delegate.parse(file))
    }
}
