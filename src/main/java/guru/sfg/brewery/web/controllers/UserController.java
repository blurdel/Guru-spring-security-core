package guru.sfg.brewery.web.controllers;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import guru.sfg.brewery.domain.security.User;
import guru.sfg.brewery.repositories.security.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Slf4j
@RequestMapping("/user")
@Controller
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;
    private final GoogleAuthenticator googleAuthenticator;


    @GetMapping("/register2fa")
    private String register2fa(Model model) {

        User user = getUser();

        // Note: createCredentials() below will call GoogleCredentialRepository.saveUserCredentials()
        String url = GoogleAuthenticatorQRGenerator.getOtpAuthURL("SFG", user.getUsername(),
                googleAuthenticator.createCredentials(getUser().getUsername()));

        log.debug("GoogleAuth QR URL: " + url);

        model.addAttribute("googleurl", url);

        return "user/register2fa";
    }

    @PostMapping("/register2fa")
    private String confirm2fa(@RequestParam Integer verifyCode) {

        User user = getUser(); // From Spring security context

        log.debug("##### register2fa Entered Code is: " + verifyCode);

        if (googleAuthenticator.authorizeUser(user.getUsername(), verifyCode)) {
            User savedUser = userRepository.findById(user.getId()).orElseThrow();
            savedUser.setUseGoogle2fa(true);
            userRepository.save(savedUser);
            return "index";
        }
        else {
            // bad code
            return "user/register2fa";
        }
    }

    @GetMapping("/verify2fa")
    public String verify2fa() {
        return "user/verify2fa";
    }

    @PostMapping("/verify2fa")
    private String verifyPostOf2fa(@RequestParam Integer verifyCode) {

        User user = getUser(); // From Spring security context

        log.debug("##### verify2fa Entered Code is: " + verifyCode);

        if (googleAuthenticator.authorizeUser(user.getUsername(), verifyCode)) {

            // Properly entered code, so can flip the flag for 2FA
            ((User) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).setGoogle2faRequired(false);

            return "/index";
        }
        else {
            // bad code, go back
            return "user/verify2fa";
        }
    }

    private User getUser() {
        return (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

}
