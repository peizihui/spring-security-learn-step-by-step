Spring Security

# 1.简介

<img src="http://q8xc9za4f.bkt.clouddn.com/cloudflare/image-20200508122331515.png" alt="image-20200508122331515" style="zoom: 50%;" />

# 2. Spring security 权限拦截

![image-20200508133228269](http://q8xc9za4f.bkt.clouddn.com/cloudflare/image-20200508133228269.png)



# 3. SpringSecurity数据库管理

![image-20200508133410120](http://q8xc9za4f.bkt.clouddn.com/cloudflare/image-20200508133410120.png)



## 3.1 Authentication

```java
Authentication
   // 获取权限集合
Collection<? extends GrantedAuthority> getAuthorities();
	 */ // 获取凭证
Object getCredentials();
 /**
	 * Stores additional details about the authentication request. These might be an IP
	 * address, certificate serial number etc.
	 *
	 * @return additional details about the authentication request, or <code>null</code>
	 * if not used
	 *
	 */
	Object getDetails();
	/**
	 * The identity of the principal being authenticated. In the case of an 		authentication
	 * request with username and password, this would be the username. Callers are
	 * expected to populate the principal for an authentication request.
	 * <p>
	 * The <tt>AuthenticationManager</tt> implementation will often return an
	 * <tt>Authentication</tt> containing richer information as the principal for use by
	 * the application. Many of the authentication providers will create a
	 * {@code UserDetails} object as the principal.
	 *
	 * @return the <code>Principal</code> being authenticated or the authenticated
	 * principal after authentication.
	 * 获取认证的实体
	 */
	Object getPrincipal();

/**
	 * Used to indicate to {@code AbstractSecurityInterceptor} whether it should present
	 * the authentication token to the <code>AuthenticationManager</code>. Typically an
	 * <code>AuthenticationManager</code> (or, more often, one of its
	 * <code>AuthenticationProvider</code>s) will return an immutable authentication token
	 * after successful authentication, in which case that token can safely return
	 * <code>true</code> to this method. Returning <code>true</code> will improve
	 * performance, as calling the <code>AuthenticationManager</code> for every request
	 * will no longer be necessary.
	 * <p>
	 * For security reasons, implementations of this interface should be very careful
	 * about returning <code>true</code> from this method unless they are either
	 * immutable, or have some way of ensuring the properties have not been changed since
	 * original creation.
	 *
	 * @return true if the token has been authenticated and the
	 * <code>AbstractSecurityInterceptor</code> does not need to present the token to the
	 * <code>AuthenticationManager</code> again for re-authentication.
	 * 是否认证通过
	 */
	boolean isAuthenticated();
	// 设置授权
	void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException;
```
## 3.2 权限缓存

<img src="Spring Security.assets/image-20200508140022574.png" alt="image-20200508140022574" style="zoom: 50%;" />

 ## 3.3  CachingUserDetailsService 

```java
  // CachingUserDetailsService

	public UserDetails loadUserByUsername(String username) {
		//1. 缓存中加载，
		UserDetails user = userCache.getUserFromCache(username);
		// 2. 数据中查询
		if (user == null) {
			user = delegate.loadUserByUsername(username);
		}

		Assert.notNull(user, () -> "UserDetailsService " + delegate
				+ " returned null for username " + username + ". "
				+ "This is an interface contract violation");
		//3. 加载结果存在缓存中；
		userCache.putUserInCache(user);

		return user;
	}
```



# 4. Spring Security 自定义决策

 **自定义决策**  AccessDecisionManager







```java
public abstract class AbstractAccessDecisionManager implements AccessDecisionManager,

	public boolean supports(ConfigAttribute attribute) {
        // AccessDecisionVoter 投票器
		for (AccessDecisionVoter voter : this.decisionVoters) {
			if (voter.supports(attribute)) {
				return true;
			}
		}

		return false;
	}

```

```java



```

**投票权具体实现类**

```java
// 投票器一半以上投票就可以通过；
public class ConsensusBased extends AbstractAccessDecisionManager { 


}
```

```java
//  所有都同意才可以进行投票；
public class UnanimousBased extends AbstractAccessDecisionManager {

}
```



```java
// 一票通过决策器
public class AffirmativeBased extends AbstractAccessDecisionManager {}
```

```java

```



```java
	affirmative 

- 英 /əˈfɜːmətɪv/  
- 美 /əˈfɜːrmətɪv/ 

adj. 肯定的；积极的

n. 肯定语；赞成的一方

复数 affirmatives

总结

      当访问的权限需要多个权限的时候，需要自己实现AccessDecisionVoter类来完成；可以参考RoleVoter
      
// 角色投票器，
public class RoleVoter implements AccessDecisionVoter<Object> {}

```



```
AccessDecisionVoter
```







# 5.DEMO

#5.1    WebSecurityConfigurerAdapter

```java

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyUserService myUserService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication().withUser("admin").password("123456").roles("ADMIN");
//        auth.inMemoryAuthentication().withUser("zhangsan").password("zhangsan").roles("ADMIN");
//        auth.inMemoryAuthentication().withUser("demo").password("demo").roles("USER");
//
        auth.userDetailsService(myUserService).passwordEncoder(new MyPasswordEncoder());

        auth.jdbcAuthentication().usersByUsernameQuery("").authoritiesByUsernameQuery("").passwordEncoder(new MyPasswordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .anyRequest().authenticated()
                .and()
                .logout().permitAll()
                .and()
                .formLogin();
        // Cross Site Request Forgery 跨站请求伪造 
        http.csrf().disable();
    }

    /**
     * 
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        // 取消权限拦截
        web.ignoring().antMatchers("/js/**", "/css/**", "/images/**");
    }
}
    
```





## 5.2  

```java
@EnableAutoConfiguration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class DemoApplication {
```







## 5.3



```
package com.mmall.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/*
<mirrors>
	<mirror>
		<id>alimaven</id>
		<name>aliyun maven</name>
		<url>http://maven.aliyun.com/nexus/content/groups/public/</url>
		<mirrorOf>central</mirrorOf>
	</mirror>
</mirrors>
 */
@SpringBootApplication
@RestController
@EnableAutoConfiguration(exclude = {DataSourceAutoConfiguration.class})
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class DemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

	@RequestMapping("/")
	public String home() {
		return "hello spring boot";
	}

	@RequestMapping("/hello")
	public String hello() {
		return "hello world";
	}
	// 注意必須有ROLE_開始，參考RoleVoter 里面配置的前缀；
	
	@PreAuthorize("hasRole('ROLE_ADMIN')")
	@RequestMapping("/roleAuth")
	public String role() {
		return "admin auth";
	}


	@PreAuthorize("#id<10 and principal.username.equals(#username) and #user.username.equals('abc')")
	@PostAuthorize("returnObject%2==0")
	@RequestMapping("/test")
	public Integer test(Integer id, String username, User user) {
		// ...
		return id;
	}

	@PreFilter("filterObject%2==0")
	@PostFilter("filterObject%4==0")
	@RequestMapping("/test2")
	public List<Integer> test2(List<Integer> idList) {
		// ...
		return idList;
	}

}

```



**RoleVoter**

```
public class RoleVoter implements AccessDecisionVoter<Object> {
    private String rolePrefix = "ROLE_";

    public RoleVoter() {
    }
```

