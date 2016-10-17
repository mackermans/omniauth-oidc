require 'omniauth'
require 'openid_connect'

module OmniAuth
  module Strategies
    class OIDC
      include OmniAuth::Strategy

      option :client_options, {
        client_id: nil,
        secret: nil,
        authorization_endpoint: "/authorize",
        token_endpoint: "/token",
        userinfo_endpoint: "/userinfo",
        jwks_uri: '/jwk'
      }
      option :redirect_uri
      option :issuer
      option :discovery, true
      option :client_signing_alg
      option :client_jwk_signing_key
      option :client_x509_signing_key
      option :scope, [:openid]
      option :response_type, "id_token"
      option :state
      option :response_mode
      option :display, nil #, [:page, :popup, :touch, :wap]
      option :prompt, nil #, [:none, :login, :consent, :select_account]
      option :hd, nil
      option :max_age
      option :ui_locales
      option :id_token_hint
      option :login_hint
      option :acr_values
      option :send_nonce, true
      option :send_scope_to_token_endpoint, true
      option :client_auth_method

      uid { user_info.sub }

      info do
        {
          name: user_info.name,
          email: user_info.email,
          nickname: user_info.preferred_username,
          first_name: user_info.given_name,
          last_name: user_info.family_name,
          gender: user_info.gender,
          image: user_info.picture,
          phone: user_info.phone_number,
          urls: { website: user_info.website }
        }
      end

      extra do
        {
          raw_info: user_info.raw_attributes
        }
      end

      credentials do
        {
            id_token: access_token.id_token,
            token: access_token.access_token,
            refresh_token: access_token.refresh_token,
            expires_in: access_token.expires_in,
            scope: access_token.scope
        }
      end

      def request_phase
        options.issuer = issuer if options.issuer.blank?
        discover! if options.discovery
        redirect authorize_uri
      end

      def callback_phase
        error = request.params['error_reason'] || request.params['error']
        if error
          raise CallbackError.new(request.params['error'], request.params['error_description'] || request.params['error_reason'], request.params['error_uri'])
        elsif request.params['state'].to_s.empty? || request.params['state'] != stored_state
          return Rack::Response.new(['401 Unauthorized'], 401).finish
        else
          options.issuer = issuer if options.issuer.blank?
          discover! if options.discovery
          client.authorization_code = authorization_code
          access_token
          super
        end
      rescue CallbackError => e
        fail!(:invalid_credentials, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end

      def client
        @client ||= ::OpenIDConnect::Client.new(options.client_options)
      end

      def config
        @config ||= ::OpenIDConnect::Discovery::Provider::Config.discover!(options.issuer)
      end

      def discover!
        options.client_options.authorization_endpoint = config.authorization_endpoint
        options.client_options.token_endpoint = config.token_endpoint
        options.client_options.userinfo_endpoint = config.userinfo_endpoint
        options.client_options.jwks_uri = config.jwks_uri
      end

      def authorize_uri
        client.authorization_uri({
            response_type: options.response_type,
            scope: options.scope,
            state: generate_state,
            nonce: generate_nonce,
        })
      end

      def access_token
        @access_token ||= begin
          client.access_token!(
            scope: (options.scope if options.send_scope_to_token_endpoint),
            client_auth_method: options.client_auth_method
          ).tap do |access_token|
            decode_id_token(access_token.id_token).verify!(
              issuer: options.issuer,
              client_id: options.client_options.identifier,
              nonce: stored_nonce
            )
          end
        end
      end

      def generate_nonce
        session['omniauth.nonce'] = SecureRandom.hex[16]
      end

      def stored_nonce
        session.delete('omniauth.nonce')
      end

      def generate_state
        session['omniauth.state'] = SecureRandom.hex[16]
      end

      def stored_state
        session.delete('omniauth.state')
      end

      def session
        @env.nil? ? {} : super
      end

      class CallbackError < StandardError
        attr_accessor :error, :error_reason, :error_uri

        def initialize(error, error_reason=nil, error_uri=nil)
          self.error = error
          self.error_reason = error_reason
          self.error_uri = error_uri
        end

        def message
          [error, error_reason, error_uri].compact.join(' | ')
        end
      end
    end
  end
end

OmniAuth.config.add_camelization('oidc', 'OIDC')
