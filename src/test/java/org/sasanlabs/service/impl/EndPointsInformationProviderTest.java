package org.sasanlabs.service.impl;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import java.net.UnknownHostException;
import java.util.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.sasanlabs.beans.AllEndPointsResponseBean;
import org.sasanlabs.beans.ScannerResponseBean;
import org.sasanlabs.configuration.VulnerableAppProperties;
import org.sasanlabs.internal.utility.EnvUtils;
import org.sasanlabs.internal.utility.MessageBundle;
import org.sasanlabs.vulnerableapp.facade.schema.VulnerabilityDefinition;

public class EndPointsInformationProviderTest {
    private EnvUtils envUtils;
    private MessageBundle messageBundle;
    private VulnerableAppProperties vulnerableAppProperties;
    private EndPointsInformationProvider provider;

    @BeforeEach
    void setUp() {
        envUtils = mock(EnvUtils.class);
        messageBundle = mock(MessageBundle.class);
        vulnerableAppProperties = mock(VulnerableAppProperties.class);
        provider =
                new EndPointsInformationProvider(
                        envUtils, messageBundle, vulnerableAppProperties, 8080);
    }

    @Test
    void testGetSupportedEndPoints_empty() throws JsonProcessingException {
        when(envUtils.getAllClassesAnnotatedWithVulnerableAppRestController())
                .thenReturn(Collections.emptyMap());
        List<AllEndPointsResponseBean> result = provider.getSupportedEndPoints();
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void testGetScannerRelatedEndPointInformation_empty()
            throws JsonProcessingException, UnknownHostException {
        when(envUtils.getAllClassesAnnotatedWithVulnerableAppRestController())
                .thenReturn(Collections.emptyMap());
        List<ScannerResponseBean> result = provider.getScannerRelatedEndPointInformation();
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void testGetVulnerabilityDefinitions_empty() throws JsonProcessingException {
        when(envUtils.getAllClassesAnnotatedWithVulnerableAppRestController())
                .thenReturn(Collections.emptyMap());
        List<VulnerabilityDefinition> result = provider.getVulnerabilityDefinitions();
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    // Additional tests can be added to mock more complex scenarios if needed
}
