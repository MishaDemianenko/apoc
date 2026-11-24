package apoc.licensepatch

import org.gradle.api.Plugin
import org.gradle.api.Project

/**
 * Keeps the unmaintained com.github.hierynomus.license plugins working on Gradle 9+.
 *
 * Applying it alongside them in the same plugins block puts the groovy.util classes of this
 * build on their classpath, replacing the ones Groovy 4 moved to groovy.xml. It also sets the
 * report destinations, whose defaults derive from ReportingExtension.getBaseDir(), which
 * Gradle 9 removed.
 */
class LicensePluginPatch implements Plugin<Project> {
    @Override
    void apply(Project project) {
        project.allprojects { p ->
            p.tasks.matching { it.name == 'downloadLicenses' }.configureEach { task ->
                def licenseReportDir = p.layout.buildDirectory.dir('reports/license').get().asFile
                task.jsonDestination = licenseReportDir
                task.htmlDestination = licenseReportDir
                task.xmlDestination = licenseReportDir
            }
        }
    }
}
