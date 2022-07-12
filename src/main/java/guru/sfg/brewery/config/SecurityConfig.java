package guru.sfg.brewery.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .authorizeRequests(authorize -> {
                    authorize
                            .antMatchers("/h2-console/**").permitAll() // TODO: DEV ONLY!!!

                            .antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll()

                            .antMatchers(HttpMethod.GET, "/api/v1/beer/**")
                                .hasAnyRole("ADMIN", "CUSTOMER", "USER")

                            .mvcMatchers(HttpMethod.DELETE, "/api/v1/beer/**").hasRole("ADMIN")
                            .mvcMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}")
                                .hasAnyRole("ADMIN", "CUSTOMER", "USER")

                            .mvcMatchers("/brewery/breweries")
                                .hasAnyRole("ADMIN", "CUSTOMER")
                            .mvcMatchers(HttpMethod.GET, "/brewery/api/v1/breweries")
                                .hasAnyRole("ADMIN", "CUSTOMER")

                            .mvcMatchers("/beers/find", "/beers/{beerId}")
                                .hasAnyRole("ADMIN", "CUSTOMER", "USER");

                })
                .authorizeRequests()
                .anyRequest().authenticated();

        http.formLogin();
        http.httpBasic();
        http.csrf().disable();

        // TODO: h2 console config = DEV ONLY!!!
        http.headers().frameOptions().sameOrigin();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // TODO: Not needed since we created our service as spring components and will be detected
//    @Autowired
//    JpaUserDetailsService userDetailsService;

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // TODO: Not needed since we created our service as spring components and will be detected
//        auth.userDetailsService(this.userDetailsService).passwordEncoder(passwordEncoder());

//        auth.inMemoryAuthentication()
//                .withUser("spring")
//                .password("{bcrypt}$2a$10$/gkFh4gqY/.K/xzls78Uz.Gnotb9lTff4E.fNz7nLbdNGxqH8mn6W")
//                .roles("ADMIN")
//
//                .and()
//                .withUser("user")
//                .password("{sha256}4395259b8d2029681733b362679c3a581eb9e90f3ad296890c072499a3270d42440cc411be11a046")
//                .roles("USER");
//
//        auth.inMemoryAuthentication().withUser("scott").password("{ldap}{SSHA}sfFa8o/QNHXlTyVGxFABEHn8WCK0f5p2Trr+Aw==").roles("CUSTOMER");
//    }


//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails admin = User.withDefaultPasswordEncoder()
//                .username("spring")
//                .password("guru")
//                .roles("ADMIN")
//                .build();
//
//        UserDetails user = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("password")
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(admin, user);
//    }

}
