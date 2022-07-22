package guru.sfg.brewery.security.listeners;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureDisabledEvent;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AuthenticationFailureListener {

    @EventListener
    public void listen(AuthenticationFailureBadCredentialsEvent event) {
        log.debug("Login failure ...");

        if (event.getSource() instanceof UsernamePasswordAuthenticationToken) {
            UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) event.getSource();

            if (token.getPrincipal() instanceof String) {
                log.debug("########## Failed login username: " + token.getPrincipal());
            }

            if (token.getDetails() instanceof WebAuthenticationDetails) {
                WebAuthenticationDetails details = (WebAuthenticationDetails) token.getDetails();
                log.debug("########## Remote Address: " + details.getRemoteAddress());
            }
        }
    }

    @EventListener
    public void listen(AuthenticationFailureDisabledEvent event) {
        log.debug("########## Login failure/disabled ... " + event.toString());
    }

}
