import SwiftUI

/// A login's tile: the first letter of its name on a colour picked from its website, or
/// from its name without one, so logins for the same site look alike. Drawn here, never
/// fetched: no server learns which sites you have logins for.
struct LoginTile: View {
    let name: String
    let url: String
    var size: CGFloat = 28
    /// Grey, for a deleted login.
    var muted = false

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: size * 0.24, style: .continuous)
        shape
            .fill((muted ? Color.gray : Self.color(for: Self.colorKey(name: name, url: url))).gradient)
            .overlay {
                Text(Self.initial(of: name))
                    .font(.system(size: size * 0.48, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white)
                    .shadow(color: .black.opacity(0.15), radius: 0.5, y: 0.5)
            }
            .overlay {
                shape.strokeBorder(.black.opacity(0.08), lineWidth: 0.5)
            }
            .frame(width: size, height: size)
            .accessibilityHidden(true)
    }

    /// The first letter or digit of the name, capitalised.
    static func initial(of name: String) -> String {
        guard let first = name.first(where: { $0.isLetter || $0.isNumber }) else { return "•" }
        return String(first).uppercased()
    }

    /// The site's domain, its last two labels ("accounts.google.com" and "google.com" match),
    /// or the name.
    static func colorKey(name: String, url: String) -> String {
        let trimmed = url.trimmingCharacters(in: .whitespaces)
        if !trimmed.isEmpty,
            let host = URL(string: trimmed.contains("://") ? trimmed : "https://\(trimmed)")?.host()
        {
            return host.lowercased().split(separator: ".").suffix(2).joined(separator: ".")
        }
        return name.lowercased()
    }

    /// The same colour for the same key on every launch: FNV-1a, as Swift's own hashing
    /// changes between launches.
    static func color(for key: String) -> Color {
        var hash: UInt64 = 0xcbf2_9ce4_8422_2325
        for byte in key.utf8 {
            hash = (hash ^ UInt64(byte)) &* 0x0000_0100_0000_01b3
        }
        return palette[Int(hash % UInt64(palette.count))]
    }

    /// Colours white letters read well on, in light and dark.
    private static let palette: [Color] = [
        .blue, .indigo, .purple, .pink, .red, .orange, .green, .teal, .brown, .gray,
    ]
}

/// A person's avatar: their initials on grey, as in Contacts.
struct Avatar: View {
    let name: String
    var size: CGFloat = 28

    var body: some View {
        Circle()
            .fill(Color.gray.gradient)
            .overlay {
                Text(Self.initials(of: name))
                    .font(.system(size: size * 0.4, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white)
            }
            .frame(width: size, height: size)
            .accessibilityHidden(true)
    }

    /// The first letter of the first and last words: "Olivia Park" is "OP", "Mo" is "M".
    static func initials(of name: String) -> String {
        let words = name.split(whereSeparator: \.isWhitespace)
        let letters = [words.first, words.count > 1 ? words.last : nil]
            .compactMap { $0?.first(where: { $0.isLetter || $0.isNumber }) }
        return letters.isEmpty ? "•" : String(letters).uppercased()
    }
}

/// A group's tile: people on indigo.
struct GroupTile: View {
    var size: CGFloat = 28

    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.24, style: .continuous)
            .fill(Color.indigo.gradient)
            .overlay {
                Image(systemName: "person.3.fill")
                    .font(.system(size: size * 0.34, weight: .semibold))
                    .foregroundStyle(.white)
            }
            .frame(width: size, height: size)
            .accessibilityHidden(true)
    }
}

/// A page's header: its picture, its name and a line about it, above its first section.
struct PageHeader<Picture: View>: View {
    let title: String
    let subtitle: String
    @ViewBuilder let picture: Picture

    var body: some View {
        HStack(spacing: 14) {
            picture
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.title2.weight(.semibold))
                    .foregroundStyle(.primary)
                    .lineLimit(2)
                Text(subtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .textCase(nil)
        .padding(.bottom, 10)
    }
}

/// What a row is about on the left, and the button for it on the right, as System Settings
/// lays out actions.
struct ActionRow: View {
    let title: String
    let button: String
    var role: ButtonRole?
    var disabled = false
    let action: () -> Void

    var body: some View {
        LabeledContent(title) {
            Button(button, role: role, action: action)
                .disabled(disabled)
        }
    }
}
