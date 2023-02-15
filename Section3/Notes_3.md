# Section 3: Defining and Managing Users

After applying the security configuration, we can define users for this application.

There are many ways to do that:

1 - Define a single static user inside the application.properties

```properties
spring.security.user.name=khaled
spring.security.user.password=123
```

Now, you can use this credential to login through the basic login form.

------------------------------------------------------------------------

2 - Define multiple static users within memory by <b><i>InMemoryUserDetailsManager</i></b>

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests().anyRequest().authenticated()
                .and().formLogin()
                .and().httpBasic();
        return http.build();
    }
    
    /*
     * The formLogin() method call enables form-based authentication,
     *  which allows users to authenticate by submitting a form containing their username and password.
     * 
     * The httpBasic() method call enables HTTP Basic authentication,
     *  which allows users to authenticate using their username and password in the HTTP request headers.
     * */


    @Bean
    InMemoryUserDetailsManager memoryUserDetailsManager(){
        UserDetails admin = User.builder()
                .username("khaled")
                .password(passwordEncoder().encode("123"))
                .authorities("admin")
                .build();

        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder().encode("123"))
                .authorities("user")
                .build();

        return new InMemoryUserDetailsManager(admin, user);
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


}

```

To make our application work, we need to:

- encode the password before storing it.
- tell the spring security what encoder we used in the authentication process

Let's take a look at tow of the encoders provided by spring security:

- BCryptPasswordEncoder: Uses a bcrypt strong hashing function to encode a password (Best solution)
- NoOpPasswordEncoder: Doesn't do anything. It only compares the strings using equals() method.

```java
    ...
public PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }
    ...
```

### Note:
The previous approaches are useful for testing (not production).
So, We usually store users in a database.

-----------------------------------------------------------------------

## Understanding user management interfaces and classes

![img.png](img.png)

#### Authentication Scenario

1 - Enter the username and password inside the browser. <b>(By login form)</b>

2 - load the user details so that you can compare with the user details that you have inside the storage system and what the end user entered inside the browser (Authentication Process). <b>(By loadUserByUsername(String username) abstract method in UserDetailsService interface)</b>


Note: 

1 - InMemoryUserDetailsManager class implements UserDetailsManager and UserDetailsPasswordService.

```java
public interface UserDetailsManager extends UserDetailsService {
    void createUser(UserDetails user);

    void updateUser(UserDetails user);

    void deleteUser(String username);

    void changePassword(String oldPassword, String newPassword);

    boolean userExists(String username);
}

public interface UserDetailsService {
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```

So, InMemoryUserDetailsManager implements loadUserByUsername: 


```java
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetails user = (UserDetails)this.users.get(username.toLowerCase());
        if (user == null) {
            throw new UsernameNotFoundException(username);
        } else {
            return new User(user.getUsername(), user.getPassword(), user.isEnabled(), user.isAccountNonExpired(), user.isCredentialsNonExpired(), user.isAccountNonLocked(), user.getAuthorities());
        }
    }
```


2 - As you see, the UserDetailsManager interface contains some useful methods to create new users in the system storage and manage them.

3 - There are some approaches to store users details (implementation classes for UserDetailsManager interface)

- InMemoryUserDetailsManager
- JdbcUserDetailsManager
- LdapUserDetailsManager


Q/ why we are loading user details from the storage system only with the username?
Why not both username, password and authorities?

Because they will be checked automatically by Spring Security.

![img_1.png](img_1.png)

-----------------------------------------------------------------------------------------------

## SecurityContextHolder

![img_3.png](img_3.png)

The SecurityContextHolder is where Spring Security stores the details of who is authenticated.

## SecurityContext
The SecurityContext is obtained from the SecurityContextHolder.
The SecurityContext contains an Authentication object.

## Authentication

The Authentication interface serves two main purposes within Spring Security:

- An input to AuthenticationManager to provide the credentials a user has provided to authenticate. When used in this scenario, isAuthenticated() returns false.

- Represent the currently authenticated user. You can obtain the current Authentication from the SecurityContext.

### The Authentication contains:

- principal: Identifies the user. When authenticating with a username/password this is often an instance of UserDetails.

- credentials: Often a password. In many cases, this is cleared after the user is authenticated, to ensure that it is not leaked.

- authorities: The GrantedAuthority instances are high-level permissions the user is granted. Two examples are roles and scopes.

## GrantedAuthority

GrantedAuthority instances are high-level permissions that the user is granted

It is an authority that is granted to the principal. Such authorities are usually “roles”,
such as ROLE_ADMINISTRATOR or ROLE_HR_SUPERVISOR.

When using username/password based authentication GrantedAuthority instances are usually loaded by the UserDetailsService.

## AuthenticationManager

AuthenticationManager is the API that defines how Spring Security’s Filters perform authentication.

While the implementation of AuthenticationManager could be anything, the most common implementation is ProviderManager.


## ProviderManager

- ProviderManager is the most commonly used implementation of AuthenticationManager.
- ProviderManager delegates to a List of AuthenticationProvider instances.
- Each AuthenticationProvider has an opportunity to indicate that authentication should be successful, fail, or indicate it cannot make a decision and allow a downstream AuthenticationProvider to decide.

![img_4.png](img_4.png)

In practice each AuthenticationProvider knows how to perform a specific type of authentication.
For example, one AuthenticationProvider might be able to validate a username/password,
while another might be able to authenticate a SAML assertion.

By default, ProviderManager tries to clear any sensitive credentials information from the Authentication object that is returned by a successful authentication request. This prevents information, such as passwords, being retained longer than necessary in the HttpSession.

## AuthenticationProvider

- You can inject multiple AuthenticationProviders instances into ProviderManager.
- Each AuthenticationProvider performs a specific type of authentication.
- For example, DaoAuthenticationProvider supports username/password-based authentication,
while JwtAuthenticationProvider supports authenticating a JWT token.

## AbstractAuthenticationProcessingFilter

AbstractAuthenticationProcessingFilter is used as a base Filter for authenticating a user’s credentials.

Before the credentials can be authenticated, Spring Security typically requests the credentials by using AuthenticationEntryPoint.

Next, the AbstractAuthenticationProcessingFilter can authenticate any authentication requests that are submitted to it.

![img_5.png](img_5.png)

1- When the user submits their credentials, the AbstractAuthenticationProcessingFilter creates an Authentication from the HttpServletRequest to be authenticated.

- The type of Authentication created depends on the subclass of AbstractAuthenticationProcessingFilter.

- For example, UsernamePasswordAuthenticationFilter creates a UsernamePasswordAuthenticationToken from a username and password that are submitted in the HttpServletRequest.


2 - Next, the Authentication is passed into the AuthenticationManager to be authenticated.

3 - If authentication fails, then Failure.

- The SecurityContextHolder is cleared out.

- RememberMeServices.loginFail is invoked. If remember me is not configured, this is a no-op. See to remember me package.

- AuthenticationFailureHandler is invoked. See the AuthenticationFailureHandler interface.


4 - If authentication is successful, then Success.

- SessionAuthenticationStrategy is notified of a new login. See the SessionAuthenticationStrategy interface.

- The Authentication is set on the SecurityContextHolder. Later, the SecurityContextPersistenceFilter saves the SecurityContext to the HttpSession. See the SecurityContextPersistenceFilter class.

- RememberMeServices.loginSuccess is invoked. If remember me is not configured, this is a no-op. See the rememberme package.

- ApplicationEventPublisher publishes an InteractiveAuthenticationSuccessEvent.

- AuthenticationSuccessHandler is invoked. See the AuthenticationSuccessHandler interface.

--------------------------------------------------------------------------------------------------------------------

## DaoAuthenticationProvider

DaoAuthenticationProvider is an AuthenticationProvider implementation that uses a UserDetailsService and PasswordEncoder to authenticate a username and password.

![img_7.png](img_7.png)

- The authentication Filter from the Reading the Username & Password section passes a UsernamePasswordAuthenticationToken to the AuthenticationManager, which is implemented by ProviderManager.

- The ProviderManager is configured to use an AuthenticationProvider of type DaoAuthenticationProvider.

- DaoAuthenticationProvider looks up the UserDetails from the UserDetailsService.

- DaoAuthenticationProvider uses the PasswordEncoder to validate the password on the UserDetails returned in the previous step.

- When authentication is successful, the Authentication that is returned is of type UsernamePasswordAuthenticationToken and has a principal that is the UserDetails returned by the configured UserDetailsService. Ultimately, the returned UsernamePasswordAuthenticationToken is set on the SecurityContextHolder by the authentication Filter.

![img_8.png](img_8.png)


![img_9.png](img_9.png)

--------------------------------------------------------------------------------------------------------------------

## Connection and creating user in DB

### Default Schema:

Spring Security provides default queries for JDBC-based authentication.

JdbcDaoImpl requires tables to load the password, account status (enabled or disabled) and a list of authorities (roles) for the user.

The default schema is also exposed as a classpath resource named org/springframework/security/core/userdetails/jdbc/users.ddl.

#### User Schema

```roomsql
create table users(
    `id` INT NOT NULL AUTO_INCREMENT,
	username varchar(50) not null,
	password varchar(500) not null,
	enabled boolean not null,
	PRIMARY KEY (`id`));

create table authorities (
   `id` INT NOT NULL AUTO_INCREMENT,
	username varchar(50) not null,
	authority varchar(50) not null,
    PRIMARY KEY (`id`),
	constraint fk_authorities_users foreign key(id) references users(id)
	);
```

#### Group Schema

If your application uses groups, you need to provide the groups schema:

```roomsql
create table groups (
	id bigint generated by default as identity(start with 0) primary key,
	group_name varchar_ignorecase(50) not null
);

create table group_authorities (
	group_id bigint not null,
	authority varchar(50) not null,
	constraint fk_group_authorities_group foreign key(group_id) references groups(id)
);

create table group_members (
	id bigint generated by default as identity(start with 0) primary key,
	username varchar(50) not null,
	group_id bigint not null,
	constraint fk_group_members_group foreign key(group_id) references groups(id)
);
```

#### JdbcUserDetailsManager Bean

```java
@Bean
UserDetailsManager users(DataSource dataSource) {
	UserDetails user = User.builder()
		.username("user")
		.password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
		.roles("USER")
		.build();
	UserDetails admin = User.builder()
		.username("admin")
		.password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
		.roles("USER", "ADMIN")
		.build();
	JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
	users.createUser(user);
	users.createUser(admin);
	return users;
}

@Bean
public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
        }

```

![img_10.png](img_10.png)

Now, you can login with these users

------------------------------------------------------------------------------------

If your DB contains user details, you will use the following method instead of the previous method.

```java
@Bean
    UserDetailsService userDetailsService(DataSource dataSource){
        return new JdbcUserDetailsManager(dataSource);
    }
```

Spring Boot will automatically create an object of data source inside my web application.

So, that's why when I try to pass this data source object to this JdbcUserDetailsManager,
so I'm telling to my JdbcUserDetailsManager there is a database that I have created and the details 
of the database is present inside this data source.

------------------------------------------------------------------------------------

### Custom Schema

You can create your custom DB Schema, but in this case you must change the default implementation 
of the loadUserByUsername abstract method in the UserDetailsService interface with your custom logic
that deals with the fields of your new schema.

You must do that in order for AuthenticationProvider to deal with your DB

[Example](../Section3/JDBCAuthentication)
