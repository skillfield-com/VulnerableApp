package org.sasanlabs.beans;

import static org.junit.jupiter.api.Assertions.*;

import java.util.*;
import org.junit.jupiter.api.Test;
import org.sasanlabs.internal.utility.Variant;
import org.sasanlabs.internal.utility.annotations.RequestParameterLocation;
import org.sasanlabs.vulnerability.types.VulnerabilityType;
import org.springframework.web.bind.annotation.RequestMethod;

public class BeansCoverageTest {
    @Test
    void testScannerResponseBean() {
        List<VulnerabilityType> types = new ArrayList<>();
        ScannerResponseBean bean =
                new ScannerResponseBean("/url", "variant", RequestMethod.GET, types);
        assertEquals("/url", bean.getUrl());
        assertEquals(RequestMethod.GET, bean.getRequestMethod());
        assertEquals(types, bean.getVulnerabilityTypes());
    }

    @Test
    void testAttackVectorResponseBean() {
        List<VulnerabilityType> types = new ArrayList<>();
        AttackVectorResponseBean bean = new AttackVectorResponseBean(types, "curl", "desc");
        assertEquals(types, bean.getVulnerabilityTypes());
        assertEquals("curl", bean.getCurlPayload());
        assertEquals("desc", bean.getDescription());
    }

    @Test
    void testAllEndPointsResponseBean() {
        AllEndPointsResponseBean bean = new AllEndPointsResponseBean();
        bean.setName("name");
        bean.setDescription("desc");
        VulnerabilityType[] types = new VulnerabilityType[] {};
        bean.setVulnerabilityTypes(types);
        Set<LevelResponseBean> set = new TreeSet<>();
        bean.setLevelDescriptionSet(set);
        assertEquals("name", bean.getName());
        assertEquals("desc", bean.getDescription());
        assertEquals(types, bean.getVulnerabilityTypes());
        assertEquals(set, bean.getLevelDescriptionSet());
    }

    @Test
    void testLevelResponseBean() {
        LevelResponseBean bean = new LevelResponseBean();
        bean.setLevel("level");
        bean.setVariant(Variant.UNSECURE);
        bean.setDescription("desc");
        bean.setHtmlTemplate("template");
        bean.setRequestParameterLocation(RequestParameterLocation.BODY);
        bean.setParameterName("param");
        bean.setSampleValues(new String[] {"a", "b"});
        bean.setRequestMethod(RequestMethod.POST);
        List<AttackVectorResponseBean> av = new ArrayList<>();
        bean.setAttackVectorResponseBeans(av);
        assertEquals("level", bean.getLevel());
        assertEquals(Variant.UNSECURE, bean.getVariant());
        assertEquals("desc", bean.getDescription());
        assertEquals("template", bean.getHtmlTemplate());
        assertEquals(RequestParameterLocation.BODY, bean.getRequestParameterLocation());
        assertEquals("param", bean.getParameterName());
        assertArrayEquals(new String[] {"a", "b"}, bean.getSampleValues());
        assertEquals(RequestMethod.POST, bean.getRequestMethod());
        assertEquals(av, bean.getAttackVectorResponseBeans());
    }

    @Test
    void testScannerMetaResponseBean() {
        List<VulnerabilityType> types = new ArrayList<>();
        List<RequestParameterLocation> locs = new ArrayList<>();
        ScannerMetaResponseBean bean = new ScannerMetaResponseBean(types, locs);
        assertEquals(types, bean.getAvailableVulnerabilityTypes());
        assertEquals(locs, bean.getAvailableLocations());
    }
}
