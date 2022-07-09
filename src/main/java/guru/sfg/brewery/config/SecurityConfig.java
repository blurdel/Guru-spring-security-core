package guru.sfg.brewery.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // Create REST header authorization filter
//    public RestHeaderAuthFilter restHeaderAuthFilter(AuthenticationManager authenticationManager){
//        RestHeaderAuthFilter filter = new RestHeaderAuthFilter(new AntPathRequestMatcher("/api/**"));
//        filter.setAuthenticationManager(authenticationManager);
//        return filter;
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests((requests) -> requests.anyRequest().authenticated());
//        http.formLogin();
//        http.httpBasic();


        // Add filter in the filter chain before UsernamePasswordAuthenticationFilter
//        http.addFilterBefore(restHeaderAuthFilter(authenticationManager()),
//                UsernamePasswordAuthenticationFilter.class)
//                .csrf().disable(); // Disable Cross-Site Request Forgery (CSRF)

        http
                .authorizeRequests(authorize -> {
                    authorize
                            .antMatchers("/h2-console/**").permitAll() // TODO: DEV ONLY!!!

                            .antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll()
                            .antMatchers("/beer/find", "/beers*").permitAll()
                            .antMatchers(HttpMethod.GET, "/api/v1/beer/**").permitAll()

                            .mvcMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}").permitAll();

                })
                .authorizeRequests()
                .anyRequest().authenticated();

        http.formLogin();
        http.httpBasic();

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
