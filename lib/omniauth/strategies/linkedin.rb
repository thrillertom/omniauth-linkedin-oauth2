require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class LinkedIn < OmniAuth::Strategies::OAuth2
      # Give your strategy a name.
      option :name, 'linkedin'

      # This is where you pass the options you would pass when
      # initializing your consumer from the OAuth gem.
      option :client_options, {
        :site => 'https://api.linkedin.com',
        :authorize_url => 'https://www.linkedin.com/uas/oauth2/authorization?response_type=code',
        :token_url => 'https://www.linkedin.com/uas/oauth2/accessToken'
      }

      option :scope, 'r_basicprofile r_emailaddress'
      option :fields, ['id', 'email-address', 'first-name', 'last-name', 'headline', 'location', 'industry', 'picture-url', 'public-profile-url']

      # These are called after authentication has succeeded. If
      # possible, you should try to set the UID without making
      # additional calls (if the user id is returned with the token
      # or as a URI parameter). This may not be possible with all
      # providers.
      uid { raw_info['id'] }

      info do
        prune! {
          :name => user_name,
          :email => raw_info['emailAddress'],
          :nickname => user_name,
          :first_name => raw_info['firstName'],
          :last_name => raw_info['lastName'],
          :location => raw_info['location'],
          :description => raw_info['headline'],
          :image => raw_info['pictureUrl'],
          :urls => {
            'public_profile' => raw_info['publicProfileUrl']
          }
        }
      end

      extra do
        hash = {}
        hash['raw_info'] = raw_info unless skip_info?
        prune! hash
      end

      alias :oauth2_access_token :access_token

      def access_token
        ::OAuth2::AccessToken.new(client, oauth2_access_token.token, {
          :mode => :query,
          :param_name => 'oauth2_access_token',
          :expires_in => oauth2_access_token.expires_in,
          :expires_at => oauth2_access_token.expires_at
        })
      end

      def raw_info
        @raw_info ||= access_token.get("/v1/people/~:(#{options.fields.join(',')})?format=json").parsed || {}
      end

      def build_access_token
        if access_token = request.params["access_token"]
          ::OAuth2::AccessToken.from_hash(client, {"access_token" => access_token})
        else
          super
        end
      end

      def request_phase
        if request_contains_secure_cookie?
          params[:access_token]  = secure_cookie['access_token']
          query = Rack::Utils.build_query(params)

          url = callback_url
          url << "?" unless url.match(/\?/)
          url << "&" unless url.match(/[\&\?]$/)
          url << query

          redirect url
        else
          super
        end
      end

      def secure_cookie
        @secure_cookie ||= raw_secure_cookie && parse_secure_cookie(raw_secure_cookie)
      end

      private

      def raw_secure_cookie
        request.cookies["linkedin_oauth_#{client.id}"]
      end

      def request_contains_secure_cookie?
        secure_cookie && secure_cookie['access_token']
      end

      def parse_secure_cookie(cookie)
        payload = JSON.parse cookie
        if valid_signature(client.secret, payload)
          payload
        end
      end

      def validate_signature(secret, payload)
        valid = false
        if payload['signature_version'] == '1'
          if payload['signature_order'].present? and payload['signature_order'].is_a?(Array)
            plain_msg = payload['signature_order'].map {|key| payload[key]}.join('')
            if payload['signature_method'] == 'HMAC-SHA1'
              signature = Base64.encode64(OpenSSL::HMAC.digest('sha1', client.secret, plain_msg)).chomp
              if signature == payload['signature']
                valid = true
              end
            end
          end
        end
        valid
      end

      def user_name
        name = "#{raw_info['firstName']} #{raw_info['lastName']}".strip
        name.empty? ? nil : name
      end

      def prune!(hash)
        hash.delete_if do |_, value|
          prune!(value) if value.is_a?(Hash)
          value.nil? || (value.respond_to?(:empty?) && value.empty?)
        end
      end
    end
  end
end

OmniAuth.config.add_camelization 'linkedin', 'LinkedIn'
