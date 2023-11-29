package com.geekpie.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author luoshi
 * @Description: AdminController
 * @date 2023-11-29 17:49
 */
@Controller
public class AdminController {
    @GetMapping("/admin/greeting")
    @Secured("admin-role")
    public void greeting(HttpServletResponse httpServletResponse) throws IOException {
        httpServletResponse.getWriter().write("hello admin!");
    }
}
