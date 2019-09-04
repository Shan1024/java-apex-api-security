package com.api.util.ApiSecurity;

import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.stream.Collectors;

/**
 * @author GDS-PDD
 */
public class ApiList extends ArrayList<Entry<String, String>> {

    private static final long serialVersionUID = 1L;

    public void add(String key, String value) {
        Entry<String, String> item = new SimpleEntry<>(key, value);
        this.add(item);
    }

    public String toString(Boolean isBaseString) {
        return this.toString("&", true, false, isBaseString);
    }

    public String toString(String delimiter, Boolean sort, Boolean quote, Boolean isBaseString) {
        List<String> list;
        String format = (quote ? "%s=\"%s\"" : "%s=%s");

        // Sort by key first, then by value.
        if (sort) {
            list = this.stream()
                    .sorted((Entry<String, String> l1, Entry<String, String> l2) ->
                            l1.getKey().equals(l2.getKey()) ? l1.getValue().compareTo(l2.getValue())
                                    : l1.getKey().compareTo(l2.getKey()))
                    .map(e -> (e.getValue() == null || (e.getValue().isEmpty()) && isBaseString) ? e.getKey() :
                            String.format(format, e.getKey(), e.getValue()))
                    .collect(Collectors.toList());
        } else {
            list = this.stream()
                    .map(e -> String.format(format, e.getKey(), e.getValue()))
                    .collect(Collectors.toList());
        }

        return String.join(delimiter, list);
    }
}
