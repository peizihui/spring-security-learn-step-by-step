package com.mmall.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * Created by jimin on 2017/8/24.
 */
@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyUserService myUserService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 基于内存的验证；

        auth.inMemoryAuthentication().withUser("admin").password("123456").roles("ADMIN");
//        auth.inMemoryAuthentication().withUser("zhangsan").password("zhangsan").roles("ADMIN");
        // 指定的角色，指定的用戶；
//        auth.inMemoryAuthentication().withUser("demo").password("demo").roles("USER");
//
        auth.userDetailsService(myUserService).passwordEncoder(new MyPasswordEncoder());

        auth.jdbcAuthentication().usersByUsernameQuery("").authoritiesByUsernameQuery("").passwordEncoder(new MyPasswordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 决定了权限如何配置； http 请求的拦截；
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .anyRequest().authenticated()
                .and()
                // 注销仍可以访问；
                .logout().permitAll()
                .and()
                // 允许表单登录；
                .formLogin();
        // 关闭csrf 认证；
        http.csrf().disable();
    }

    /**
     *
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        // 取消权限拦截静态资源；
        web.ignoring().antMatchers("/js/**", "/css/**", "/images/**");
    }
}
